from database import Database
from nessus_connector import NessusConnector
import requests
from config import Config

class Orchestrator:
    """Business logic and workflow orchestration"""
    
    def __init__(self):
        self.db = Database()
        self.nessus = NessusConnector()
    
    def import_nessus_scan(self, nessus_scan_id):
        """Import scan results from Nessus into database"""
        scan_details = self.nessus.get_scan_details(nessus_scan_id)
        
        if not scan_details:
            return None
        
        # Create scan record
        scan_id = f"scan_{nessus_scan_id}"
        scan_info = scan_details.get('info', {})
        # Inject object_id so parse_vulnerabilities can fetch per-host data
        scan_details['info']['object_id'] = nessus_scan_id
        
        self.db.add_scan(
            scan_id=scan_id,
            name=scan_info.get('name', 'Imported Scan'),
            target=scan_info.get('targets', 'Unknown'),
            status='completed',
            nessus_scan_id=nessus_scan_id
        )
        
        # Parse and store vulnerabilities
        vulnerabilities = self.nessus.parse_vulnerabilities(scan_details)
        
        for vuln in vulnerabilities:
            self.db.add_vulnerability(
                scan_id=scan_id,
                plugin_id=vuln['plugin_id'],
                name=vuln['name'],
                severity=vuln['severity'],
                host=vuln.get('host', scan_info.get('targets', 'Unknown')),
                port=vuln.get('port', ''),
                description=vuln.get('description', ''),
                solution=vuln.get('solution', '')
            )
        
        return scan_id
    
    def prioritize_vulnerabilities(self, scan_id):
        """Prioritize vulnerabilities based on severity and context"""
        vulns = self.db.get_vulnerabilities_by_scan(scan_id)
        
        # Sort by severity priority
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        
        prioritized = sorted(
            vulns,
            key=lambda v: severity_order.get(v[4], 5)  # v[4] is severity column
        )
        
        return prioritized
    
    def trigger_ai_remediation(self, vulnerability_id):
        """Trigger AI agent for vulnerability remediation"""
        case_id = self.db.create_remediation_case(vulnerability_id)

        # Get vulnerability details to pass host info to agent
        conn = self.db.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT name, host FROM vulnerabilities WHERE id = ?', (vulnerability_id,))
        vuln = cursor.fetchone()
        conn.close()

        vuln_name = vuln[0] if vuln else ''
        host = vuln[1] if vuln else ''

        try:
            response = requests.post(
                f'{Config.AI_AGENT_ENDPOINT}/remediate',
                json={
                    'vulnerability_id': vulnerability_id,
                    'vulnerability_name': vuln_name,
                    'host': host
                },
                timeout=300
            )

            if response.status_code == 200:
                result = response.json()
                self.db.update_remediation_case(
                    case_id=case_id,
                    status='completed' if result.get('success') else 'failed',
                    agent_output=str(result),
                    verification_status='verified' if result.get('success') else 'failed'
                )
                return {'success': result.get('success', False), 'case_id': case_id}
            else:
                self.db.update_remediation_case(case_id=case_id, status='failed',
                                                agent_output=f'HTTP {response.status_code}')
                return {'success': False, 'error': 'Agent request failed'}

        except Exception as e:
            self.db.update_remediation_case(case_id=case_id, status='failed', agent_output=str(e))
            return {'success': False, 'error': str(e)}
    
    def verify_remediation(self, case_id, scan_id):
        """Verify if remediation was successful via Metasploit or rescan"""
        # Placeholder for verification logic
        # Could trigger Metasploit exploit attempt or Nessus rescan
        self.db.update_remediation_case(
            case_id=case_id,
            status='completed',
            verification_status='verified'
        )
        return True
    
    def deduplicate_vulnerabilities(self, host):
        """Merge duplicate vulnerabilities for the same host"""
        # Placeholder for deduplication logic
        pass
