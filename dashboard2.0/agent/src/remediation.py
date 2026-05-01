"""Remediation actions for MS17-010 vulnerability."""

from dataclasses import dataclass
from enum import Enum
from loguru import logger

from src.winrm_client import WinRMClient


class RemediationStatus(Enum):
    """Status of a remediation action."""

    SUCCESS = "success"
    FAILED = "failed"
    ALREADY_FIXED = "already_fixed"
    SKIPPED = "skipped"


@dataclass
class RemediationResult:
    """Result of a remediation action."""

    status: RemediationStatus
    message: str
    details: str = ""


class SMBv1Remediation:
    """Handles SMBv1 disabling to remediate MS17-010 vulnerability."""

    # PowerShell script to check if SMBv1 is enabled
    CHECK_SMBV1_SCRIPT = """
    $smbv1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($smbv1) {
        $smbv1.State
    } else {
        # Fallback for older Windows versions
        $regValue = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
        if ($regValue -and $regValue.SMB1 -eq 0) {
            "Disabled"
        } else {
            "Enabled"
        }
    }
    """

    # PowerShell script to disable SMBv1
    DISABLE_SMBV1_SCRIPT = """
    $ErrorActionPreference = "Stop"
    try {
        # Modify the registry key to disable SMBv1 server
        Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force
        Write-Output "Registry key modified to disable SMBv1 server"
        
        # Restart the LanmanServer service to apply changes immediately (synchronous operation)
        Restart-Service -Name "LanmanServer" -Force
        Write-Output "LanmanServer service restarted successfully"
        
        # Configure the SMB1 client to be disabled
        sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
        sc.exe config mrxsmb10 start= disabled
        Write-Output "SMB1 client configured and disabled"
        
        Write-Output "SUCCESS: SMBv1 has been completely disabled and service restarted"
    } catch {
        Write-Error "FAILED: $($_.Exception.Message)"
        exit 1
    }
    """

    def __init__(self, client: WinRMClient):
        """Initialize the remediation handler.

        Args:
            client: Connected WinRM client for the target host.
        """
        self.client = client

    def check_smbv1_status(self) -> bool:
        """Check if SMBv1 is currently enabled on the target.

        Returns:
            True if SMBv1 is enabled, False if disabled.
        """
        result = self.client.run_powershell(self.CHECK_SMBV1_SCRIPT)
        if result.success:
            status = result.stdout.strip().lower()
            is_enabled = status == "enabled"
            logger.info(f"SMBv1 status: {'Enabled' if is_enabled else 'Disabled'}")
            return is_enabled
        else:
            logger.warning(f"Could not determine SMBv1 status: {result.stderr}")
            return True  # Assume enabled if we can't check

    def disable_smbv1(self, dry_run: bool = False) -> RemediationResult:
        """Disable SMBv1 on the target machine.

        Args:
            dry_run: If True, only check status without making changes.

        Returns:
            RemediationResult with status and details.
        """
        logger.info(f"Starting SMBv1 remediation on {self.client.host}")

        # First check current status
        if not self.check_smbv1_status():
            return RemediationResult(
                status=RemediationStatus.ALREADY_FIXED,
                message="SMBv1 is already disabled",
            )

        if dry_run:
            return RemediationResult(
                status=RemediationStatus.SKIPPED,
                message="Dry run - SMBv1 would be disabled",
                details="SMBv1 is currently enabled",
            )

        # Execute the remediation
        logger.info("Executing SMBv1 disable script...")
        result = self.client.run_powershell(self.DISABLE_SMBV1_SCRIPT)

        if result.success and "SUCCESS" in result.stdout:
            logger.success(f"SMBv1 disabled successfully on {self.client.host}")
            return RemediationResult(
                status=RemediationStatus.SUCCESS,
                message="SMBv1 has been disabled successfully",
                details=result.stdout,
            )
        else:
            logger.error(f"Failed to disable SMBv1: {result.stderr}")
            return RemediationResult(
                status=RemediationStatus.FAILED,
                message="Failed to disable SMBv1",
                details=result.stderr or result.stdout,
            )

    def requires_reboot(self) -> bool:
        """Check if a reboot is required for changes to take effect.

        Returns:
            True if reboot is required.
        """
        script = """
        $reboot = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" -Name "RebootPending" -ErrorAction SilentlyContinue
        if ($reboot) { "True" } else { "False" }
        """
        result = self.client.run_powershell(script)
        return result.stdout.strip().lower() == "true"
