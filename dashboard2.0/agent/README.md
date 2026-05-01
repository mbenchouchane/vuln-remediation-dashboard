# MS17-010 Remediation Agent

An AI-powered security remediation agent that automates the correction of the MS17-010 (EternalBlue) vulnerability by disabling SMBv1 on Windows machines.

## Overview

This agent provides a proactive, self-healing security approach by:

1. **Receiving alerts** from Splunk or Nessus vulnerability scan results
2. **Connecting** to target Windows machines via WinRM (Windows Remote Management)
3. **Executing** PowerShell commands to disable SMBv1
4. **Verifying** that the fix has been applied
5. **Scanning** to confirm the vulnerability has been eliminated

This automation significantly reduces the time between detection and remediation.

## Getting Started

### Prerequisites

- Python 3.10+
- WinRM enabled on target Windows machines
- Network access to target machines
- Appropriate credentials for remote administration

### Installation

```bash
pip install -r requirements.txt
```

### Configuration

Create a `.env` file with your configuration:

```env
# Alert source configuration
SPLUNK_HOST=your-splunk-host
SPLUNK_TOKEN=your-splunk-token
NESSUS_HOST=your-nessus-host
NESSUS_API_KEY=your-nessus-api-key

# WinRM credentials
WINRM_USERNAME=administrator
WINRM_PASSWORD=your-password
```

### Usage

```bash
# Run the agent
python -m src.main

# Or remediate a specific host
python -m src.main --target 192.168.1.100
```

## Project Structure

```
ai-agent/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── agent.py
│   ├── alert_handler.py
│   ├── winrm_client.py
│   ├── remediation.py
│   └── verification.py
├── tests/
│   └── __init__.py
├── config/
│   └── settings.py
├── requirements.txt
└── README.md
```

## Security Considerations

- Store credentials securely using environment variables or a secrets manager
- Use HTTPS for WinRM connections in production
- Implement proper logging and audit trails
- Test in a non-production environment first

## License

MIT
