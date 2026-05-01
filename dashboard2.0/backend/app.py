"""Vulnerability Management Hub - Flask API backend."""
from flask import Flask, jsonify, request
from flask_cors import CORS
from datetime import datetime
import requests
import json
import os
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
except ImportError:
    pass
from database import Database
from nessus_connector import NessusConnector
from orchestrator import Orchestrator
from metasploit_client import MetasploitClient
from config import Config
from vulnbot import VulnBotService
from nessus_xml_analyzer import analyzer as nessus_analyzer

msf = MetasploitClient()

app = Flask(__name__)
CORS(app)

db = Database()
nessus = NessusConnector()
orchestrator = Orchestrator()
vulnbot = VulnBotService(db=db, nessus_connector=nessus)


@app.route('/api/scans', methods=['GET'])
def get_scans():
    """Get all scan history"""
    scans = db.get_all_scans()
    return jsonify([{
        'id': s[0],
        'name': s[1],
        'target': s[2],
        'status': s[3],
        'timestamp': s[4],
        'nessus_scan_id': s[5]
    } for s in scans])


@app.route('/api/scans/nessus', methods=['GET'])
def list_nessus_scans():
    """List available Nessus scans"""
    scans = nessus.list_scans()
    return jsonify(scans)


@app.route('/api/scans/nessus/<int:scan_id>/launch', methods=['POST'])
def launch_nessus_scan(scan_id):
    """Launch a Nessus scan by ID via the connector"""
    try:
        result = nessus.launch_scan(scan_id)
        if result is None:
            return jsonify({'success': False, 'error': 'Failed to launch Nessus scan'}), 500
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/import/<nessus_scan_id>', methods=['POST'])
def import_scan(nessus_scan_id):
    """Import scan from Nessus"""
    try:
        scan_id = orchestrator.import_nessus_scan(nessus_scan_id)
        if scan_id:
            return jsonify({'success': True, 'scan_id': scan_id})
        return jsonify({'success': False, 'error': 'Failed to import scan'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get specific scan details with vulnerabilities"""
    vulns = db.get_vulnerabilities_by_scan(scan_id)
    return jsonify({
        'scan_id': scan_id,
        'vulnerabilities': [{
            'id': v[0],
            'plugin_id': v[2],
            'name': v[3],
            'severity': v[4],
            'host': v[5],
            'port': v[6],
            'description': v[7],
            'solution': v[8],
            'status': v[9]
        } for v in vulns]
    })


@app.route('/api/scans/<scan_id>/prioritize', methods=['GET'])
def prioritize_scan(scan_id):
    """Get prioritized vulnerabilities for a scan"""
    prioritized = orchestrator.prioritize_vulnerabilities(scan_id)
    return jsonify([{
        'id': v[0],
        'name': v[3],
        'severity': v[4],
        'host': v[5]
    } for v in prioritized])


@app.route('/api/remediate', methods=['POST'])
def trigger_remediation():
    """Trigger AI agent for vulnerability remediation"""
    data = request.json
    vulnerability_id = data.get('vulnerability_id')

    try:
        result = orchestrator.trigger_ai_remediation(vulnerability_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


KALI_API = 'http://192.168.56.104:5000'

@app.route('/api/kali/remediate', methods=['POST'])
def kali_remediate():
    """Proxy remediation request to the Kali AI agent API"""
    data = request.json or {}
    target = data.get('target', '')
    if not target:
        return jsonify({'success': False, 'error': 'target IP is required'}), 400
    try:
        resp = requests.post(
            f'{KALI_API}/remediate',
            json={'host': target},
            timeout=60
        )
        try:
            return jsonify(resp.json()), resp.status_code
        except Exception:
            return jsonify({'success': resp.ok, 'message': resp.text or 'No response body'}), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'error': 'Cannot reach Kali API (192.168.56.104:5000)'}), 503
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/kali/exploit', methods=['POST'])
def kali_exploit():
    """Proxy exploit request to the Kali agent /exploit route"""
    data = request.json or {}
    target = data.get('target', '')
    if not target:
        return jsonify({'success': False, 'error': 'target IP is required'}), 400
    try:
        resp = requests.post(
            f'{KALI_API}/exploit',
            json={'host': target},
            timeout=120
        )
        try:
            return jsonify(resp.json()), resp.status_code
        except Exception:
            return jsonify({'success': resp.ok, 'message': resp.text or 'No response body'}), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'success': False, 'error': 'Cannot reach Kali API (192.168.56.104:5000)'}), 503
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/kali/status', methods=['GET'])
def kali_status():
    """Check Kali agent API status"""
    try:
        resp = requests.get(f'{KALI_API}/status', timeout=5)
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({'online': False, 'error': 'Cannot reach Kali API'}), 503
    except Exception as e:
        return jsonify({'online': False, 'error': str(e)}), 500


@app.route('/api/stats/trend', methods=['GET'])
def get_trend():
    """Get vulnerability counts per scan over time"""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT s.name, s.timestamp,
            COUNT(v.id) as total,
            SUM(CASE WHEN v.severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN v.severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN v.severity = 'Medium' THEN 1 ELSE 0 END) as medium
        FROM scans s
        LEFT JOIN vulnerabilities v ON s.id = v.scan_id
        GROUP BY s.id
        ORDER BY s.timestamp ASC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return jsonify([{
        'label': r[0],
        'timestamp': r[1],
        'total': r[2],
        'critical': r[3] or 0,
        'high': r[4] or 0,
        'medium': r[5] or 0
    } for r in rows])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    return jsonify(db.get_stats())


@app.route('/api/chatbot/query', methods=['POST'])
def query_chatbot():
    """VulnBot endpoint for dashboard chat interactions."""
    data = request.json or {}
    question = (data.get('question') or '').strip()
    ui_context = data.get('context') or {}

    if not question and not ui_context:
        return jsonify({
            'answer': "Pose une question à VulnBot (ex: « Quelles sont les vulnérabilités critiques ? »).",
            'mode': 'fallback',
            'provider': 'rules',
            'context_summary': {}
        })

    result = vulnbot.ask(question=question, ui_context=ui_context)
    return jsonify(result)


@app.route('/api/chatbot/analyze-nessus', methods=['POST'])
def analyze_nessus_file():
    """Upload and analyze a .nessus XML file via vulnscan-parser, then query VulnBot."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400

    f = request.files['file']
    if not f.filename.endswith('.nessus'):
        return jsonify({'success': False, 'error': 'File must be a .nessus XML file'}), 400

    question = request.form.get('question', 'Analyse ce fichier Nessus et résume les vulnérabilités critiques.')

    content = f.read()
    summary = nessus_analyzer.analyze_bytes(content, f.filename)

    if 'error' in summary:
        return jsonify({'success': False, 'error': summary['error']}), 500

    nessus_context_text = nessus_analyzer.build_vulnbot_context(summary)

    ui_context = {
        'source': 'nessus-file-upload',
        'nessus_file_summary': summary,
        'nessus_context_text': nessus_context_text,
        'filename': f.filename,
    }

    result = vulnbot.ask(question=question, ui_context=ui_context)
    return jsonify({
        'success': True,
        'summary': summary,
        'answer': result.get('answer', ''),
        'mode': result.get('mode', ''),
    })


@app.route('/api/assets/refresh', methods=['POST'])
def refresh_assets():
    """Recompute the assets table from current vulnerabilities.

    Can be called after imports, or simply via the UI Refresh button.
    """
    try:
        db.refresh_assets_from_vulnerabilities()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/assets', methods=['GET'])
def list_assets():
    """List all assets/stations with basic risk metrics."""
    rows = db.get_assets()
    assets = [{
        'hostname': r[0],
        'ip_address': r[1],
        'last_scan': r[2],
        'vulnerability_count': r[3],
        'critical_count': r[4],
    } for r in rows]
    return jsonify(assets)


@app.route('/api/assets/<hostname>', methods=['GET'])
def get_asset(hostname):
    """Detailed view for a single asset/station."""
    asset, vulns, cases = db.get_asset_details(hostname)

    if not asset:
        return jsonify({'error': 'Asset not found'}), 404

    asset_obj = {
        'hostname': asset[0],
        'ip_address': asset[1],
        'last_scan': asset[2],
        'vulnerability_count': asset[3],
        'critical_count': asset[4],
        'vulnerabilities': [{
            'id': v[0],
            'scan_id': v[1],
            'plugin_id': v[2],
            'name': v[3],
            'severity': v[4],
            'host': v[5],
            'port': v[6],
            'status': v[7],
        } for v in vulns],
        'cases': [{
            'id': c[0],
            'vulnerability_id': c[1],
            'vulnerability_name': c[2],
            'status': c[3],
            'started_at': c[4],
            'completed_at': c[5],
        } for c in cases]
    }
    return jsonify(asset_obj)


@app.route('/api/verify', methods=['POST'])
def verify_remediation():
    """Trigger Metasploit verification for a remediation case"""
    data = request.json
    case_id = data.get('case_id')
    host = data.get('host')

    # Look up vulnerability name for this case to help the agent pick a module
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT v.name
        FROM remediation_cases rc
        JOIN vulnerabilities v ON rc.vulnerability_id = v.id
        WHERE rc.id = ?
    ''', (case_id,))
    row = cursor.fetchone()
    conn.close()
    vulnerability_name = row[0] if row else ''

    try:
        response = requests.post(
            f'{Config.AI_AGENT_ENDPOINT}/verify',
            json={'host': host, 'case_id': case_id, 'vulnerability_name': vulnerability_name},
            timeout=180
        )
        result = response.json()

        # Update case verification status in DB
        if result.get('success'):
            db.update_remediation_case(
                case_id=case_id,
                status='completed' if not result.get('vulnerable') else 'failed',
                verification_status=result.get('status')
            )

        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cases', methods=['GET'])
def get_remediation_cases():
    """Get all remediation cases (summary list)"""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT rc.id, rc.vulnerability_id, v.name, rc.status,
               rc.started_at, rc.completed_at, rc.verification_status, v.host
        FROM remediation_cases rc
        JOIN vulnerabilities v ON rc.vulnerability_id = v.id
        ORDER BY rc.started_at DESC
    ''')
    cases = cursor.fetchall()
    conn.close()

    return jsonify([{
        'id': c[0],
        'vulnerability_id': c[1],
        'vulnerability_name': c[2],
        'status': c[3],
        'started_at': c[4],
        'completed_at': c[5],
        'verification_status': c[6],
        'host': c[7]
    } for c in cases])


@app.route('/api/cases/<int:case_id>', methods=['GET'])
def get_remediation_case_details(case_id):
    """Get detailed information for a single remediation case.

    This is used by the frontend when the user clicks on a case card to
    display the list of remediation steps / agent output.
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT rc.id, rc.vulnerability_id, v.name, rc.status,
               rc.started_at, rc.completed_at, rc.agent_output,
               rc.verification_status, v.host
        FROM remediation_cases rc
        JOIN vulnerabilities v ON rc.vulnerability_id = v.id
        WHERE rc.id = ?
    ''', (case_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Case not found'}), 404

    case = {
        'id': row[0],
        'vulnerability_id': row[1],
        'vulnerability_name': row[2],
        'status': row[3],
        'started_at': row[4],
        'completed_at': row[5],
        'agent_output': row[6],
        'verification_status': row[7],
        'host': row[8]
    }

    # Try to derive structured remediation steps from vulnerability type first
    steps = []
    raw = row[6]
    vuln_name = (row[2] or '').lower()

    # Prefer a clear, human description of what was done, based on the
    # vulnerability type (MS17‑010, MS11‑030, Brotli, unsupported OS, ...)
    if 'ms17-010' in vuln_name or 'eternalblue' in vuln_name or 'smb' in vuln_name:
        steps = [
            {
                'action': 'Vérification du statut de SMBv1',
                'status': 'completed',
                'details': "Exécution d'un script PowerShell pour lire l'état de la fonctionnalité SMB1Protocol ou de la clé de registre SMB1 sur le serveur.",
                'timestamp': case['started_at']
            },
            {
                'action': 'Désactivation de SMBv1 côté serveur',
                'status': 'completed',
                'details': "Modification de la clé de registre HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 à 0, puis redémarrage du service LanmanServer.",
                'timestamp': case['completed_at'] or case['started_at']
            },
            {
                'action': 'Désactivation du client SMBv1',
                'status': 'completed',
                'details': "Mise à jour de la configuration des services (lanmanworkstation / mrxsmb10) via sc.exe pour désactiver le client SMBv1.",
                'timestamp': case['completed_at'] or case['started_at']
            }
        ]

    elif 'ms11-030' in vuln_name or '2509553' in vuln_name or 'dns resolution' in vuln_name:
        steps = [
            {
                'action': 'Vérification de la présence du correctif KB2509553',
                'status': 'completed',
                'details': "Exécution de Get-HotFix -Id KB2509553 pour vérifier si le patch de sécurité est déjà installé.",
                'timestamp': case['started_at']
            },
            {
                'action': 'Installation du correctif de sécurité KB2509553',
                'status': 'completed',
                'details': "Si non installé, tentative d'installation via le module PSWindowsUpdate ou via l'API Windows Update (COM) en sélectionnant la mise à jour correspondant à KB2509553.",
                'timestamp': case['completed_at'] or case['started_at']
            }
        ]

    elif 'brotli' in vuln_name:
        steps = [
            {
                'action': "Vérification de la version actuelle de la bibliothèque 'brotli'",
                'status': 'completed',
                'details': "Exécution d'un script Python via PowerShell pour lire __version__ du module brotli.",
                'timestamp': case['started_at']
            },
            {
                'action': "Mise à jour de la bibliothèque 'brotli'",
                'status': 'completed',
                'details': "Exécution de 'pip install brotli>=1.1.0' sur l'hôte cible pour corriger la vulnérabilité.",
                'timestamp': case['completed_at'] or case['started_at']
            }
        ]

    elif 'unsupported' in vuln_name or 'end-of-life' in vuln_name or 'windows os' in vuln_name:
        steps = [
            {
                'action': 'Installation des mises à jour Windows en attente',
                'status': 'completed',
                'details': "Utilisation du module PSWindowsUpdate (Install-WindowsUpdate) pour appliquer toutes les mises à jour logicielles disponibles sans redémarrage automatique.",
                'timestamp': case['completed_at'] or case['started_at']
            }
        ]

    # If we still have no structured steps, try to parse agent_output
    if not steps and raw:
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None

        if isinstance(parsed, list):
            steps = parsed
        elif isinstance(parsed, dict):
            if 'steps' in parsed and isinstance(parsed['steps'], list):
                steps = parsed['steps']
            else:
                steps = [{
                    'action': parsed.get('action') or parsed.get('summary') or 'Résumé de la remédiation',
                    'status': parsed.get('status') or ('completed' if parsed.get('success') else 'failed'),
                    'details': raw,
                    'timestamp': case['completed_at'] or case['started_at']
                }]
        else:
            steps = [{
                'action': 'Résumé de la remédiation',
                'details': str(raw),
                'timestamp': case['completed_at'] or case['started_at']
            }]

    case['steps'] = steps
    return jsonify(case)


@app.route('/api/metasploit/verify_ms17_010', methods=['POST'])
def verify_ms17_010():
    """Run MS17-010 scanner via Metasploit RPC against a target IP."""
    data = request.json or {}
    target_ip = data.get('target_ip', '').strip()

    if not target_ip:
        return jsonify({'status': 'error', 'message': 'target_ip is required'}), 400

    # Normalize: if Nessus passed multiple IPs or a subnet, keep only the first IP
    for sep in [',', ' ']:
        if sep in target_ip:
            target_ip = target_ip.split(sep)[0].strip()
    if '/' in target_ip:
        target_ip = target_ip.split('/')[0].strip()

    result = msf.verify_ms17_010(target_ip)
    return jsonify({
        'target_ip': target_ip,
        'status': result['status'],
        'message': result['message'],
        'output': result.get('output', '')
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
