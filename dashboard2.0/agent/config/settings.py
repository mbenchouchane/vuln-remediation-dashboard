"""Configuration settings for the remediation agent."""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Application settings loaded from environment variables."""

    # Nessus configuration
    NESSUS_HOST: str = os.getenv("NESSUS_HOST", "")
    NESSUS_API_KEY: str = os.getenv("NESSUS_API_KEY", "")

    # Metasploit RPC configuration
    METASPLOIT_HOST: str = os.getenv("METASPLOIT_HOST", "127.0.0.1")
    METASPLOIT_PORT: int = int(os.getenv("METASPLOIT_PORT", "55553"))
    METASPLOIT_PASSWORD: str = os.getenv("METASPLOIT_PASSWORD", "msf")

    # WinRM configuration
    WINRM_USERNAME: str = os.getenv("WINRM_USERNAME", "vboxuser")
    WINRM_PASSWORD: str = os.getenv("WINRM_PASSWORD", "Choch17!")
    WINRM_TRANSPORT: str = os.getenv("WINRM_TRANSPORT", "ntlm")
    WINRM_PORT: int = int(os.getenv("WINRM_PORT", "5985"))

    # Target hosts (comma-separated)
    TARGET_HOSTS: list[str] = os.getenv(
        "TARGET_HOSTS", "192.168.56.106,192.168.56.108"
    ).split(",")

    # Agent configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    DRY_RUN: bool = os.getenv("DRY_RUN", "false").lower() == "true"


settings = Settings()
