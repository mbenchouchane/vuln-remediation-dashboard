import os

class Config:
    # Nessus Configuration — set via environment variables
    NESSUS_URL        = os.getenv('NESSUS_URL',        'https://192.168.56.104:8834')
    NESSUS_ACCESS_KEY = os.getenv('NESSUS_ACCESS_KEY', '')
    NESSUS_SECRET_KEY = os.getenv('NESSUS_SECRET_KEY', '')

    # AI Agent Configuration
    AI_AGENT_ENDPOINT = os.getenv('AI_AGENT_ENDPOINT', 'http://localhost:8000')

    # VulnBot (chatbot) configuration
    VULNBOT_INCLUDE_LIVE_NESSUS  = os.getenv('VULNBOT_INCLUDE_LIVE_NESSUS', 'false').lower() == 'true'
    VULNBOT_MAX_CONTEXT_VULNS    = int(os.getenv('VULNBOT_MAX_CONTEXT_VULNS', '25'))

    VULNBOT_LLM_PROVIDER = os.getenv('VULNBOT_LLM_PROVIDER', 'openai')
    VULNBOT_LLM_API_KEY  = os.getenv('VULNBOT_LLM_API_KEY',  '')
    VULNBOT_LLM_MODEL    = os.getenv('VULNBOT_LLM_MODEL',    'google/gemini-2.0-flash-exp:free')
    VULNBOT_LLM_ENDPOINT = os.getenv('VULNBOT_LLM_ENDPOINT', 'https://openrouter.ai/api/v1')

    # Metasploit RPC (running on Kali)
    MSF_HOST = os.getenv('MSF_HOST', '192.168.56.104')
    MSF_PORT = int(os.getenv('MSF_PORT', '55553'))
    MSF_USER = os.getenv('MSF_USER', 'msf')
    MSF_PASS = os.getenv('MSF_PASS', '')
    MSF_SSL  = os.getenv('MSF_SSL',  'true').lower() == 'true'

    # Database
    SCANS_DIR = 'scans'
