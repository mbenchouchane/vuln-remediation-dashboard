import sqlite3
from datetime import datetime
import json

class Database:
    def __init__(self, db_path='vuln_management.db'):
        self.db_path = db_path
        self.init_db()
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def init_db(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                nessus_scan_id TEXT
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                plugin_id TEXT,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                host TEXT,
                port TEXT,
                description TEXT,
                solution TEXT,
                status TEXT DEFAULT 'open',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # Remediation cases table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediation_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                agent_output TEXT,
                verification_status TEXT,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
            )
        ''')
        
        # Assets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                last_scan TEXT,
                vulnerability_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_scan(self, scan_id, name, target, status, nessus_scan_id=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        # Delete existing scan and its vulnerabilities before re-importing
        cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        cursor.execute('''
            INSERT INTO scans (id, name, target, status, timestamp, nessus_scan_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, name, target, status, datetime.now().isoformat(), nessus_scan_id))
        conn.commit()
        conn.close()
    
    def update_scan_status(self, scan_id, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('UPDATE scans SET status = ? WHERE id = ?', (status, scan_id))
        conn.commit()
        conn.close()
    
    def get_all_scans(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scans ORDER BY timestamp DESC')
        scans = cursor.fetchall()
        conn.close()
        return scans
    
    def add_vulnerability(self, scan_id, plugin_id, name, severity, host, port, description, solution):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (scan_id, plugin_id, name, severity, host, port, description, solution)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, plugin_id, name, severity, host, port, description, solution))
        conn.commit()
        vuln_id = cursor.lastrowid
        conn.close()
        return vuln_id
    
    def get_vulnerabilities_by_scan(self, scan_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        vulns = cursor.fetchall()
        conn.close()
        return vulns
    
    def create_remediation_case(self, vulnerability_id):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO remediation_cases (vulnerability_id, status, started_at)
            VALUES (?, 'in_progress', ?)
        ''', (vulnerability_id, datetime.now().isoformat()))
        conn.commit()
        case_id = cursor.lastrowid
        conn.close()
        return case_id
    
    def update_remediation_case(self, case_id, status, agent_output=None, verification_status=None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE remediation_cases 
            SET status = ?, completed_at = ?, agent_output = ?, verification_status = ?
            WHERE id = ?
        ''', (status, datetime.now().isoformat(), agent_output, verification_status, case_id))
        conn.commit()
        conn.close()
    
    def get_stats(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM scans')
        total_scans = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE status = "open"')
        open_vulns = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "Critical"')
        critical_vulns = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "High" AND status = "open"')
        high_vulns = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "Medium" AND status = "open"')
        medium_vulns = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "Low" AND status = "open"')
        low_vulns = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM remediation_cases WHERE status = "in_progress"')
        active_remediations = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_scans': total_scans,
            'open_vulnerabilities': open_vulns,
            'critical_vulnerabilities': critical_vulns,
            'high_vulnerabilities': high_vulns,
            'medium_vulnerabilities': medium_vulns,
            'low_vulnerabilities': low_vulns,
            'active_remediations': active_remediations
        }

    # ---- Assets / Stations helpers ----

    def refresh_assets_from_vulnerabilities(self):
        """Rebuild the assets table based on current vulnerabilities.

        This keeps, for each host, counts of total and critical vulns and
        the date of the last scan that touched this host.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Clear assets table and rebuild from vulnerabilities
        cursor.execute('DELETE FROM assets')

        cursor.execute('''
            INSERT INTO assets (hostname, ip_address, last_scan, vulnerability_count, critical_count)
            SELECT
                COALESCE(v.host, 'Unknown') AS hostname,
                COALESCE(v.host, 'Unknown') AS ip_address,
                MAX(s.timestamp) AS last_scan,
                COUNT(*) AS vulnerability_count,
                SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            GROUP BY COALESCE(v.host, 'Unknown')
        ''')

        conn.commit()
        conn.close()

    def get_assets(self):
        """Return all assets with basic risk metrics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT hostname, ip_address, last_scan, vulnerability_count, critical_count
            FROM assets
            ORDER BY critical_count DESC, vulnerability_count DESC
        ''')
        rows = cursor.fetchall()
        conn.close()
        return rows

    def get_asset_details(self, hostname):
        """Return detailed info for a single asset/station.

        - Basic asset row
        - All vulnerabilities for this host
        - All remediation cases linked to vulnerabilities on this host
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT hostname, ip_address, last_scan, vulnerability_count, critical_count
            FROM assets
            WHERE hostname = ?
        ''', (hostname,))
        asset = cursor.fetchone()

        # Vulns for this host
        cursor.execute('''
            SELECT id, scan_id, plugin_id, name, severity, host, port, status
            FROM vulnerabilities
            WHERE host = ?
        ''', (hostname,))
        vulns = cursor.fetchall()

        # Remediation cases for this host (via vulnerability_id join)
        cursor.execute('''
            SELECT rc.id, rc.vulnerability_id, v.name, rc.status, rc.started_at, rc.completed_at
            FROM remediation_cases rc
            JOIN vulnerabilities v ON rc.vulnerability_id = v.id
            WHERE v.host = ?
            ORDER BY rc.started_at DESC
        ''', (hostname,))
        cases = cursor.fetchall()

        conn.close()

        return asset, vulns, cases
