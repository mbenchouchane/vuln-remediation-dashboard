"""WinRM client for connecting to Windows machines."""

from dataclasses import dataclass
from typing import Optional
import winrm
from loguru import logger

from config.settings import settings


@dataclass
class CommandResult:
    """Result of a remote command execution."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Check if the command executed successfully."""
        return self.exit_code == 0


class WinRMClient:
    """Client for executing remote commands on Windows machines via WinRM."""

    def __init__(
        self,
        host: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        transport: Optional[str] = None,
        port: Optional[int] = None,
    ):
        """Initialize the WinRM client.

        Args:
            host: Target Windows machine hostname or IP.
            username: Username for authentication (defaults to settings).
            password: Password for authentication (defaults to settings).
            transport: WinRM transport method (defaults to settings).
            port: WinRM port (defaults to settings).
        """
        self.host = host
        self.username = username or settings.WINRM_USERNAME
        self.password = password or settings.WINRM_PASSWORD
        self.transport = transport or settings.WINRM_TRANSPORT
        self.port = port or settings.WINRM_PORT
        self._session: Optional[winrm.Session] = None

    def connect(self) -> bool:
        """Establish a connection to the remote host.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            endpoint = f"http://{self.host}:{self.port}/wsman"
            self._session = winrm.Session(
                endpoint,
                auth=(self.username, self.password),
                transport=self.transport,
            )
            # Test connection with a simple command
            result = self._session.run_ps("$env:COMPUTERNAME")
            if result.status_code == 0:
                computer_name = result.std_out.decode().strip()
                logger.info(f"Connected to {computer_name} ({self.host})")
                return True
            else:
                logger.error(f"Connection test failed: {result.std_err.decode()}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {e}")
            return False

    def run_powershell(self, script: str) -> CommandResult:
        """Execute a PowerShell script on the remote host.

        Args:
            script: PowerShell script to execute.

        Returns:
            CommandResult with exit code, stdout, and stderr.
        """
        if not self._session:
            logger.error("Not connected. Call connect() first.")
            return CommandResult(exit_code=-1, stdout="", stderr="Not connected")

        try:
            logger.debug(f"Executing PowerShell: {script[:100]}...")
            result = self._session.run_ps(script)
            return CommandResult(
                exit_code=result.status_code,
                stdout=result.std_out.decode("utf-8", errors="replace"),
                stderr=result.std_err.decode("utf-8", errors="replace"),
            )
        except Exception as e:
            logger.error(f"PowerShell execution failed: {e}")
            return CommandResult(exit_code=-1, stdout="", stderr=str(e))

    def run_cmd(self, command: str) -> CommandResult:
        """Execute a CMD command on the remote host.

        Args:
            command: CMD command to execute.

        Returns:
            CommandResult with exit code, stdout, and stderr.
        """
        if not self._session:
            logger.error("Not connected. Call connect() first.")
            return CommandResult(exit_code=-1, stdout="", stderr="Not connected")

        try:
            logger.debug(f"Executing CMD: {command}")
            result = self._session.run_cmd(command)
            return CommandResult(
                exit_code=result.status_code,
                stdout=result.std_out.decode("utf-8", errors="replace"),
                stderr=result.std_err.decode("utf-8", errors="replace"),
            )
        except Exception as e:
            logger.error(f"CMD execution failed: {e}")
            return CommandResult(exit_code=-1, stdout="", stderr=str(e))

    def close(self) -> None:
        """Close the WinRM session."""
        self._session = None
        logger.debug(f"Closed connection to {self.host}")
