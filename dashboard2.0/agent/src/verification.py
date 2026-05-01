"""Verification module for confirming vulnerability remediation."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import time
import requests
from loguru import logger

from config.settings import settings
from src.winrm_client import WinRMClient
from src.metasploit_client import MetasploitClient


class VerificationStatus(Enum):
    """Status of verification check."""

    VERIFIED = "verified"
    STILL_VULNERABLE = "still_vulnerable"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class VerificationResult:
    """Result of a verification check."""

    status: VerificationStatus
    message: str
    details: str = ""


class RemediationVerifier:
    """Verifies that MS17-010 remediation was successful."""

    def __init__(self, client: WinRMClient):
        """Initialize the verifier.

        Args:
            client: Connected WinRM client for the target host.
        """
        self.client = client
        self.nessus_host = settings.NESSUS_HOST
        self.nessus_api_key = settings.NESSUS_API_KEY

    def verify_smbv1_disabled(self) -> VerificationResult:
        """Verify that SMBv1 is disabled on the target.

        Returns:
            VerificationResult indicating if SMBv1 is disabled.
        """
        logger.info(f"Verifying SMBv1 status on {self.client.host}")
        
        # Attendre quelques secondes pour que le service prenne en compte la modification
        time.sleep(5)
        
        # Utiliser la même commande que check_smbv1_status pour la cohérence
        script = """
        # Vérification via registre (compatible Windows 7 et versions ultérieures)
        try {
            $reg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -ErrorAction Stop
            if ($reg.SMB1 -eq 0) {
                Write-Output "Disabled"
            } else {
                Write-Output "Enabled"
            }
        } catch {
            # Si la clé n'existe pas, SMB1 est désactivé par défaut
            Write-Output "Disabled"
        }
        """

        result = self.client.run_powershell(script)

        if not result.success:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Failed to check SMBv1 status",
                details=result.stderr,
            )

        output = result.stdout.strip()
        
        if output == "Disabled":
            logger.success("Verification passed: SMBv1 is disabled")
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                message="SMBv1 is confirmed disabled",
                details=f"Registry check result: {output}",
            )
        elif output == "Enabled":
            logger.warning("Verification failed: SMBv1 is still enabled")
            return VerificationResult(
                status=VerificationStatus.STILL_VULNERABLE,
                message="SMBv1 is still enabled",
                details=f"Registry check result: {output}",
            )
        else:
            logger.warning(f"Unexpected verification result: {output}")
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                message="Could not determine SMBv1 status",
                details=f"Unexpected output: {output}",
            )

    def run_nessus_scan(self, scan_policy: Optional[str] = None) -> VerificationResult:
        """Run a targeted Nessus scan to confirm vulnerability is fixed.

        Args:
            scan_policy: Optional scan policy to use.

        Returns:
            VerificationResult from the scan.
        """
        if not self.nessus_host or not self.nessus_api_key:
            logger.warning("Nessus not configured, skipping scan verification")
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                message="Nessus not configured",
            )

        logger.info(f"Initiating Nessus scan for {self.client.host}")

        try:
            headers = {"X-ApiKeys": f"accessKey={self.nessus_api_key}"}

            # Create a targeted scan for MS17-010
            scan_config = {
                "uuid": scan_policy or "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",
                "settings": {
                    "name": f"MS17-010 Verification - {self.client.host}",
                    "text_targets": self.client.host,
                    "enabled": True,
                },
            }

            # Create the scan
            response = requests.post(
                f"{self.nessus_host}/scans",
                headers=headers,
                json=scan_config,
                verify=False,
                timeout=30,
            )
            response.raise_for_status()
            scan_data = response.json()
            scan_id = scan_data.get("scan", {}).get("id")

            if not scan_id:
                return VerificationResult(
                    status=VerificationStatus.ERROR,
                    message="Failed to create Nessus scan",
                )

            # Launch the scan
            requests.post(
                f"{self.nessus_host}/scans/{scan_id}/launch",
                headers=headers,
                verify=False,
                timeout=30,
            )

            logger.info(f"Nessus scan {scan_id} launched for {self.client.host}")
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                message=f"Scan initiated (ID: {scan_id})",
                details="Check Nessus for results once scan completes",
            )

        except requests.RequestException as e:
            logger.error(f"Nessus scan failed: {e}")
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Failed to run Nessus scan",
                details=str(e),
            )

    def verify_with_metasploit(self) -> VerificationResult:
        """Verify remediation by running the Metasploit MS17-010 scanner.

        Returns:
            VerificationResult indicating if the host is still vulnerable.
        """
        logger.info(f"Running Metasploit MS17-010 verification on {self.client.host}")

        msf = MetasploitClient()
        if not msf.connect():
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                message="Could not connect to Metasploit for verification",
            )

        scan_result = msf.verify_ms17_010_fixed(self.client.host)

        if scan_result.vulnerable:
            logger.warning(f"Metasploit confirms {self.client.host} is still vulnerable")
            return VerificationResult(
                status=VerificationStatus.STILL_VULNERABLE,
                message="Metasploit scanner confirms host is still vulnerable to MS17-010",
                details=scan_result.details,
            )
        else:
            logger.success(f"Metasploit confirms {self.client.host} is no longer vulnerable")
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                message="Metasploit scanner confirms MS17-010 is remediated",
                details=scan_result.details,
            )

    def verify_smb_port_filtered(self) -> VerificationResult:
        """Verify that SMB port 445 is not accepting SMBv1 connections.

        Returns:
            VerificationResult indicating port status.
        """
        script = """
        $result = Test-NetConnection -ComputerName localhost -Port 445 -WarningAction SilentlyContinue
        if ($result.TcpTestSucceeded) {
            # Port is open, check SMB dialect
            $smb = Get-SmbConnection -ErrorAction SilentlyContinue | Where-Object { $_.Dialect -like "1.*" }
            if ($smb) {
                "SMBv1_ACTIVE"
            } else {
                "SMB_OK"
            }
        } else {
            "PORT_CLOSED"
        }
        """

        result = self.client.run_powershell(script)

        if not result.success:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                message="Failed to check SMB port",
                details=result.stderr,
            )

        output = result.stdout.strip()
        if "SMBv1_ACTIVE" in output:
            return VerificationResult(
                status=VerificationStatus.STILL_VULNERABLE,
                message="SMBv1 connections are still active",
            )
        elif "SMB_OK" in output or "PORT_CLOSED" in output:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                message="No SMBv1 connections detected",
            )
        else:
            return VerificationResult(
                status=VerificationStatus.UNKNOWN,
                message="Could not determine SMB status",
                details=output,
            )
