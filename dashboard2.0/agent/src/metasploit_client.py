"""Metasploit RPC client for vulnerability scanning and verification."""

import time
from dataclasses import dataclass, field
from typing import Optional
from loguru import logger

from config.settings import settings


@dataclass
class ScanResult:
    """Result of a Metasploit scan."""

    host: str
    vulnerable: bool
    details: str = ""


class MetasploitClient:
    """Client for interacting with Metasploit via the MSFRPC API."""

    MS17_010_MODULE = "auxiliary/scanner/smb/smb_ms17_010"
    SCAN_POLL_INTERVAL = 5  # seconds between status checks
    SCAN_TIMEOUT = 120  # max seconds to wait for a scan

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        password: Optional[str] = None,
    ):
        """Initialize the Metasploit RPC client.

        Args:
            host: MSFRPC host (defaults to settings).
            port: MSFRPC port (defaults to settings).
            password: MSFRPC password (defaults to settings).
        """
        self.host = host or settings.METASPLOIT_HOST
        self.port = port or settings.METASPLOIT_PORT
        self.password = password or settings.METASPLOIT_PASSWORD
        self._client = None

    def connect(self) -> bool:
        """Connect to the Metasploit RPC daemon.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            from pymetasploit3.msfrpc import MsfRpcClient

            self._client = MsfRpcClient(
                self.password,
                server=self.host,
                port=self.port,
                ssl=False,
            )
            logger.info(f"Connected to Metasploit RPC at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Metasploit RPC: {e}")
            return False

    def scan_ms17_010(self, hosts: list[str]) -> list[ScanResult]:
        """Run the MS17-010 scanner against a list of hosts.

        Args:
            hosts: List of target IPs or hostnames.

        Returns:
            List of ScanResult for each host.
        """
        if not self._client:
            logger.error("Not connected. Call connect() first.")
            return [ScanResult(host=h, vulnerable=False, details="Not connected") for h in hosts]

        rhosts = " ".join(hosts)
        logger.info(f"Running MS17-010 scan against: {rhosts}")

        try:
            console = self._client.consoles.console()
            console.write(f"use {self.MS17_010_MODULE}\n")
            console.write(f"set RHOSTS {rhosts}\n")
            console.write("run\n")

            # Wait for the scan to finish
            output = ""
            elapsed = 0
            while elapsed < self.SCAN_TIMEOUT:
                time.sleep(self.SCAN_POLL_INTERVAL)
                elapsed += self.SCAN_POLL_INTERVAL
                data = console.read()
                output += data["data"]
                if data["busy"] is False:
                    break

            console.destroy()
            logger.debug(f"Metasploit scan output:\n{output}")

            # Parse results: look for lines indicating vulnerability
            results = []
            for host in hosts:
                # The scanner prints "[+] <host>:<port> - Host is likely VULNERABLE"
                vulnerable = f"{host}" in output and "VULNERABLE" in output
                details = ""
                for line in output.splitlines():
                    if host in line:
                        details += line.strip() + "\n"
                results.append(ScanResult(
                    host=host,
                    vulnerable=vulnerable,
                    details=details.strip(),
                ))
                status = "VULNERABLE" if vulnerable else "not vulnerable"
                logger.info(f"MS17-010 scan result for {host}: {status}")

            return results

        except Exception as e:
            logger.error(f"MS17-010 scan failed: {e}")
            return [ScanResult(host=h, vulnerable=False, details=str(e)) for h in hosts]

    def verify_ms17_010_fixed(self, host: str) -> ScanResult:
        """Verify that a host is no longer vulnerable to MS17-010.

        Runs the scanner on a single host and returns the result.

        Args:
            host: Target IP or hostname.

        Returns:
            ScanResult indicating whether the host is still vulnerable.
        """
        results = self.scan_ms17_010([host])
        if results:
            return results[0]
        return ScanResult(host=host, vulnerable=False, details="Scan returned no results")
