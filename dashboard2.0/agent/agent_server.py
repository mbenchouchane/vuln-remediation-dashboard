"""HTTP server that exposes the AI remediation agent as a REST API."""

import sys
import os

# Add agent src to path
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, jsonify, request
from flask_cors import CORS
from loguru import logger

from src.agent import RemediationAgent
from src.alert_handler import AlertHandler
from src.metasploit_client import MetasploitClient
from config.settings import settings

app = Flask(__name__)
CORS(app)


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'running',
        'targets': settings.TARGET_HOSTS
    })


@app.route('/verify', methods=['POST'])
def verify():
    """Verify remediation via Metasploit MS17-010 scanner.

    Expected payload: { "host": "192.168.56.108", "case_id": 1 }
    """
    data = request.json or {}
    host = data.get('host')
    case_id = data.get('case_id')

    if not host:
        return jsonify({'success': False, 'error': 'host is required'}), 400

    logger.info(f"Verification request for host={host}, case_id={case_id}")

    try:
        msf = MetasploitClient()
        if not msf.connect():
            return jsonify({
                'success': False,
                'status': 'error',
                'message': 'Could not connect to Metasploit RPC'
            })

        result = msf.verify_ms17_010_fixed(host)
        return jsonify({
            'success': True,
            'host': host,
            'case_id': case_id,
            'vulnerable': result.vulnerable,
            'status': 'still_vulnerable' if result.vulnerable else 'verified',
            'details': result.details
        })

    except Exception as e:
        logger.error(f"Verification error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/remediate', methods=['POST'])
def remediate():
    """Trigger remediation for a vulnerability.

    Expected payload:
    {
        "vulnerability_id": "...",   # from dashboard DB
        "host": "192.168.56.106",    # target host (optional, uses settings if omitted)
        "vulnerability_name": "..."  # e.g. MS17-010
    }
    """
    data = request.json or {}
    host = data.get('host')
    vulnerability_name = data.get('vulnerability_name', '')
    vulnerability_id = data.get('vulnerability_id')

    logger.info(f"Remediation request: vuln_id={vulnerability_id}, host={host}, name={vulnerability_name}")

    try:
        agent = RemediationAgent()

        if host:
            # Remediate specific host
            success = agent.remediate_host(host)
            return jsonify({
                'success': success,
                'host': host,
                'vulnerability_id': vulnerability_id,
                'message': 'Remediation completed' if success else 'Remediation failed'
            })
        else:
            # Run against all configured target hosts
            results = agent.run()
            return jsonify({
                'success': results['failed'] == 0,
                'vulnerability_id': vulnerability_id,
                'total': results['total'],
                'remediated': results['success'],
                'failed': results['failed'],
                'hosts': results['hosts']
            })

    except Exception as e:
        logger.error(f"Remediation error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/remediate/host/<host>', methods=['POST'])
def remediate_host(host):
    """Remediate a specific host directly."""
    dry_run = request.args.get('dry_run', 'false').lower() == 'true'

    if dry_run:
        settings.DRY_RUN = True

    try:
        agent = RemediationAgent()
        success = agent.remediate_host(host)
        return jsonify({
            'success': success,
            'host': host,
            'dry_run': dry_run
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("Starting AI Remediation Agent Server on port 8000...")
    logger.info(f"Target hosts: {settings.TARGET_HOSTS}")
    app.run(host='0.0.0.0', port=8000, debug=False)
