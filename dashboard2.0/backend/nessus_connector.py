import requests
import urllib3
from config import Config

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NessusConnector:
    def __init__(self):
        self.url = Config.NESSUS_URL
        self.access_key = Config.NESSUS_ACCESS_KEY
        self.secret_key = Config.NESSUS_SECRET_KEY
        self.headers = {
            'X-ApiKeys': f'accessKey={self.access_key}; secretKey={self.secret_key}',
            'Content-Type': 'application/json'
        }
    
    def list_scans(self):
        """List all scans from Nessus"""
        try:
            response = requests.get(
                f'{self.url}/scans',
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            return response.json().get('scans', [])
        except Exception as e:
            print(f"Error listing scans: {e}")
            return []
    
    def launch_scan(self, scan_id):
        """Launch a specific scan"""
        try:
            response = requests.post(
                f'{self.url}/scans/{scan_id}/launch',
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error launching scan: {e}")
            return None
    
    def get_scan_details(self, scan_id):
        """Get detailed scan results"""
        try:
            response = requests.get(
                f'{self.url}/scans/{scan_id}',
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error getting scan details: {e}")
            return None
    
    def export_scan(self, scan_id, format='nessus'):
        """Export scan results"""
        try:
            # Request export
            response = requests.post(
                f'{self.url}/scans/{scan_id}/export',
                headers=self.headers,
                json={'format': format},
                verify=False
            )
            response.raise_for_status()
            file_id = response.json()['file']
            
            # Download export
            response = requests.get(
                f'{self.url}/scans/{scan_id}/export/{file_id}/download',
                headers=self.headers,
                verify=False
            )
            response.raise_for_status()
            return response.content
        except Exception as e:
            print(f"Error exporting scan: {e}")
            return None
    
    def parse_vulnerabilities(self, scan_details):
        """Parse vulnerabilities from scan details, with per-host info"""
        vulnerabilities = []

        if not scan_details:
            return vulnerabilities

        # Build host_id -> hostname map
        hosts = scan_details.get('hosts', [])
        host_map = {h['host_id']: h.get('hostname', 'unknown') for h in hosts}

        # Fetch per-host vulnerability details
        scan_id = scan_details.get('info', {}).get('object_id')

        for host in hosts:
            host_id = host['host_id']
            hostname = host.get('hostname', 'unknown')

            try:
                response = requests.get(
                    f'{self.url}/scans/{scan_id}/hosts/{host_id}',
                    headers=self.headers,
                    verify=False
                )
                if response.status_code != 200:
                    continue
                host_details = response.json()

                for vuln in host_details.get('vulnerabilities', []):
                    description = (
                        vuln.get('description')
                        or vuln.get('plugin_description')
                        or ''
                    )
                    solution = (
                        vuln.get('solution')
                        or vuln.get('plugin_solution')
                        or ''
                    )
                    vulnerabilities.append({
                        'plugin_id': vuln.get('plugin_id'),
                        'name': vuln.get('plugin_name'),
                        'severity': self._map_severity(vuln.get('severity')),
                        'host': hostname,
                        'port': str(vuln.get('port', '')),
                        'description': description,
                        'solution': solution,
                    })
            except Exception as e:
                print(f"Error fetching host {host_id} details: {e}")

        return vulnerabilities
    
    def _map_severity(self, severity_code):
        """Map Nessus severity codes to readable names"""
        severity_map = {
            0: 'Info',
            1: 'Low',
            2: 'Medium',
            3: 'High',
            4: 'Critical'
        }
        return severity_map.get(severity_code, 'Unknown')
