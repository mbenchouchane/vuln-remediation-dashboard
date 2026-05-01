"""MS17-010 Remediation Agent implementation."""

from typing import Optional
from loguru import logger

from config.settings import settings
from src.alert_handler import AlertHandler, VulnerabilityAlert
from src.winrm_client import WinRMClient
from src.remediation import SMBv1Remediation, RemediationStatus
from src.verification import RemediationVerifier, VerificationStatus


class RemediationAgent:
    """AI agent that automates MS17-010 vulnerability remediation."""

    def __init__(self):
        """Initialize the remediation agent."""
        self.alert_handler = AlertHandler()
        self.dry_run = settings.DRY_RUN

    def process_alert(self, alert: VulnerabilityAlert) -> bool:
        """Process a single vulnerability alert.

        Args:
            alert: The vulnerability alert to process.

        Returns:
            True if remediation was successful, False otherwise.
        """
        logger.info(f"Processing alert for {alert.host}: {alert.vulnerability_id}")

        # Connect to the target host
        client = WinRMClient(alert.host)
        if not client.connect():
            logger.error(f"Failed to connect to {alert.host}")
            return False

        try:
            # Perform remediation
            remediation = SMBv1Remediation(client)
            result = remediation.disable_smbv1(dry_run=self.dry_run)

            if result.status in (RemediationStatus.SUCCESS, RemediationStatus.ALREADY_FIXED):
                # Verify the fix
                verifier = RemediationVerifier(client)
                verification = verifier.verify_smbv1_disabled()

                if verification.status == VerificationStatus.VERIFIED:
                    logger.success(f"Remediation verified for {alert.host}")

                    # Optionally run a Nessus scan for additional verification
                    if settings.NESSUS_HOST:
                        verifier.run_nessus_scan()

                    # Run Metasploit verification scan
                    msf_result = verifier.verify_with_metasploit()
                    if msf_result.status == VerificationStatus.STILL_VULNERABLE:
                        logger.warning(f"Metasploit verification failed for {alert.host}: {msf_result.message}")
                        return False

                    # Check if reboot is required
                    if remediation.requires_reboot():
                        logger.warning(f"Reboot required on {alert.host} for changes to take full effect")

                    return True
                else:
                    logger.warning(f"Verification failed for {alert.host}: {verification.message}")
                    return False
            else:
                logger.error(f"Remediation failed for {alert.host}: {result.message}")
                return False

        finally:
            client.close()

    def remediate_host(self, host: str) -> bool:
        """Remediate a specific host.

        Args:
            host: Target host IP or hostname.

        Returns:
            True if remediation was successful.
        """
        alert = self.alert_handler.create_manual_alert(host)
        return self.process_alert(alert)

    def run(self, target: Optional[str] = None) -> dict:
        """Run the remediation agent.

        Args:
            target: Optional specific target host. If not provided,
                   fetches alerts from configured sources.

        Returns:
            Summary of remediation results.
        """
        logger.info("MS17-010 Remediation Agent starting...")

        results = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "hosts": [],
        }

        if target:
            # Remediate specific host
            alerts = [self.alert_handler.create_manual_alert(target)]
        else:
            # Fetch alerts from configured sources (Nessus + Metasploit)
            alerts = self.alert_handler.get_all_alerts()

            # If no alerts from external sources, use default target hosts
            if not alerts and settings.TARGET_HOSTS:
                logger.info(f"No external alerts; using default target hosts: {settings.TARGET_HOSTS}")
                alerts = [self.alert_handler.create_manual_alert(h) for h in settings.TARGET_HOSTS]

        if not alerts:
            logger.info("No alerts to process")
            return results

        results["total"] = len(alerts)
        logger.info(f"Processing {len(alerts)} alert(s)")

        for alert in alerts:
            success = self.process_alert(alert)
            if success:
                results["success"] += 1
            else:
                results["failed"] += 1
            results["hosts"].append({
                "host": alert.host,
                "success": success,
            })

        logger.info(
            f"Remediation complete: {results['success']}/{results['total']} successful"
        )
        return results
