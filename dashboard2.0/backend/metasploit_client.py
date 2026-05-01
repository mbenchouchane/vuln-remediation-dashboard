"""Metasploit RPC client — restricted to MS17-010 scanner only."""
import time
import requests
import urllib3
from config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALLOWED_MODULE = "auxiliary/scanner/smb/smb_ms17_010"


class MetasploitClient:
    def __init__(self):
        proto = "https" if Config.MSF_SSL else "http"
        self.url = f"{proto}://{Config.MSF_HOST}:{Config.MSF_PORT}/api/1.0"
        self.token = None

    # ------------------------------------------------------------------ #
    def _post(self, method, *params):
        payload = [method, self.token] + list(params) if self.token else [method] + list(params)
        # Metasploit msgrpc uses MessagePack-RPC over HTTP, not JSON.
        # We send/receive MessagePack payloads.
        import msgpack
        resp = requests.post(
            self.url,
            data=msgpack.packb(payload),
            headers={"Content-Type": "binary/message-pack"},
            verify=False,
            timeout=30
        )
        resp.raise_for_status()
        data = msgpack.unpackb(resp.content, raw=False)
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(data.get("error_message", "Metasploit RPC error"))
        return data

    # ------------------------------------------------------------------ #
    def connect(self):
        """Authenticate and store session token."""
        result = self._post("auth.login", Config.MSF_USER, Config.MSF_PASS)
        self.token = result["token"]

    def disconnect(self):
        if self.token:
            try:
                self._post("auth.logout", self.token)
            except Exception:
                pass
            self.token = None

    # ------------------------------------------------------------------ #
    def verify_ms17_010(self, target_ip: str) -> dict:
        """
        Run auxiliary/scanner/smb/smb_ms17_010 against target_ip.
        Returns {"status": "vulnerable"|"not_vulnerable"|"error", "message": str}
        """
        try:
            self.connect()

            # Create a temporary console
            console = self._post("console.create")
            cid = str(console["id"])

            # Send module commands
            commands = (
                f"use {ALLOWED_MODULE}\n"
                f"set RHOSTS {target_ip}\n"
                "set RPORT 445\n"
                "set THREADS 1\n"
                "run\n"
            )
            self._post("console.write", cid, commands)

            # Poll until the console is idle (module finished)
            output = ""
            for _ in range(60):          # max 60 × 3 s = 3 min
                time.sleep(3)
                data = self._post("console.read", cid)
                output += data.get("data", "")
                if not data.get("busy", True):
                    break

            # Destroy console
            self._post("console.destroy", cid)
            self.disconnect()

            return self._parse_output(output, target_ip)

        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_output(output: str, target_ip: str) -> dict:
        lower = output.lower()
        if "is vulnerable" in lower or "vulnerable to ms17-010" in lower:
            return {
                "status": "vulnerable",
                "message": f"{target_ip} is VULNERABLE to MS17-010 (EternalBlue)",
                "output": output.strip()[-800:]
            }
        if "not vulnerable" in lower or "host does not appear" in lower:
            return {
                "status": "not_vulnerable",
                "message": f"{target_ip} is NOT vulnerable to MS17-010",
                "output": output.strip()[-800:]
            }
        # Module ran but result is ambiguous
        return {
            "status": "error",
            "message": "Module ran but result could not be determined",
            "output": output.strip()[-800:]
        }
