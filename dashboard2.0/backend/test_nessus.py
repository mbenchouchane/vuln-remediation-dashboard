from nessus_connector import NessusConnector

n = NessusConnector()
scans = n.list_scans()

if scans is not None:
    print(f"Connected! Scans found: {len(scans)}")
    for s in scans:
        print(f"  - [{s.get('id')}] {s.get('name')} | status: {s.get('status')}")
else:
    print("Connection failed - check URL and API keys")
