"""
SilentSeal - Incident Playbooks & One-Click Export
Prebuilt playbooks (PII leak, compliance request) and evidence export.
"""
import os, json, hashlib, time, sqlite3
from typing import Dict, List, Any
from datetime import datetime, timezone


BUILTIN_PLAYBOOKS = {
    'pii_leak_response': {
        'name': 'PII Leak Response',
        'description': 'Respond to a detected PII leak incident',
        'severity': 'CRITICAL',
        'steps': [
            {'order': 1, 'action': 'Identify', 'detail': 'Confirm the PII leak — what data, which file, what entity types'},
            {'order': 2, 'action': 'Contain', 'detail': 'Quarantine the affected file (Encrypt & Quarantine)'},
            {'order': 3, 'action': 'Assess', 'detail': 'Determine scope: how many records, how many data subjects affected'},
            {'order': 4, 'action': 'Notify', 'detail': 'Alert DPO/Admin within 72 hours (GDPR) or as required'},
            {'order': 5, 'action': 'Remediate', 'detail': 'Redact or delete the PII from affected systems'},
            {'order': 6, 'action': 'Document', 'detail': 'Export evidence bundle (signed logs, timeline, affected entities)'},
            {'order': 7, 'action': 'Review', 'detail': 'Post-incident review — update detection rules to prevent recurrence'},
        ]
    },
    'dsar_compliance': {
        'name': 'Data Subject Access Request (DSAR)',
        'description': 'Handle a GDPR/DPDP data subject access or deletion request',
        'severity': 'HIGH',
        'steps': [
            {'order': 1, 'action': 'Verify Identity', 'detail': 'Confirm the requestor identity'},
            {'order': 2, 'action': 'Search', 'detail': 'Run system scan for all files containing the data subject PII'},
            {'order': 3, 'action': 'Compile', 'detail': 'Generate data subject report with all occurrences'},
            {'order': 4, 'action': 'Review', 'detail': 'Review findings with legal/compliance team'},
            {'order': 5, 'action': 'Execute', 'detail': 'Delete or redact as requested, or provide data export'},
            {'order': 6, 'action': 'Respond', 'detail': 'Send response to data subject within deadline'},
            {'order': 7, 'action': 'Log', 'detail': 'Record all actions in audit trail for compliance'},
        ]
    },
    'unauthorized_access': {
        'name': 'Unauthorized Access Response',
        'description': 'Respond to unauthorized access to sensitive files',
        'severity': 'CRITICAL',
        'steps': [
            {'order': 1, 'action': 'Detect', 'detail': 'Identify unauthorized access from audit logs'},
            {'order': 2, 'action': 'Revoke', 'detail': 'Revoke access tokens and lock vault'},
            {'order': 3, 'action': 'Investigate', 'detail': 'Review access logs to determine scope'},
            {'order': 4, 'action': 'Contain', 'detail': 'Rotate encryption keys if needed'},
            {'order': 5, 'action': 'Report', 'detail': 'Export incident evidence and notify stakeholders'},
        ]
    }
}


class IncidentPlaybook:
    """Prebuilt incident response playbooks with evidence export."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'playbooks.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.export_dir = os.path.join(os.path.dirname(__file__), '..', 'exports')
        os.makedirs(self.export_dir, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS playbook_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id TEXT UNIQUE, playbook_id TEXT, incident_id TEXT,
            status TEXT DEFAULT 'in_progress', current_step INTEGER DEFAULT 1,
            step_results TEXT, started_at TEXT, completed_at TEXT, executed_by TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS custom_playbooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            playbook_id TEXT UNIQUE, name TEXT, description TEXT,
            severity TEXT, steps TEXT, created_at TEXT, created_by TEXT)''')
        conn.commit()
        conn.close()

    def list_playbooks(self) -> List[Dict]:
        playbooks = [{'id': k, **{key: v[key] for key in ['name', 'description', 'severity']},
                       'steps_count': len(v['steps']), 'type': 'builtin'}
                      for k, v in BUILTIN_PLAYBOOKS.items()]
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        custom = conn.execute('SELECT * FROM custom_playbooks').fetchall()
        conn.close()
        for c in custom:
            steps = json.loads(c['steps'])
            playbooks.append({'id': c['playbook_id'], 'name': c['name'],
                              'description': c['description'], 'severity': c['severity'],
                              'steps_count': len(steps), 'type': 'custom'})
        return playbooks

    def get_playbook(self, playbook_id: str) -> Dict:
        if playbook_id in BUILTIN_PLAYBOOKS:
            return {'id': playbook_id, **BUILTIN_PLAYBOOKS[playbook_id], 'type': 'builtin'}
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute('SELECT * FROM custom_playbooks WHERE playbook_id=?', (playbook_id,)).fetchone()
        conn.close()
        if row:
            return {'id': row['playbook_id'], 'name': row['name'], 'description': row['description'],
                    'severity': row['severity'], 'steps': json.loads(row['steps']), 'type': 'custom'}
        return {'error': 'Playbook not found'}

    def execute_playbook(self, playbook_id: str, incident_id: str = None,
                         executed_by: str = 'system') -> Dict:
        pb = self.get_playbook(playbook_id)
        if 'error' in pb:
            return pb
        eid = hashlib.sha256(f"exec:{playbook_id}:{time.time()}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT INTO playbook_executions
            (execution_id, playbook_id, incident_id, status, current_step, step_results, started_at, executed_by)
            VALUES (?,?,?,?,?,?,?,?)''',
            (eid, playbook_id, incident_id or eid, 'in_progress', 1,
             json.dumps([]), datetime.now(timezone.utc).isoformat(), executed_by))
        conn.commit()
        conn.close()
        return {'execution_id': eid, 'playbook': pb['name'], 'status': 'in_progress',
                'total_steps': len(pb['steps']), 'current_step': 1,
                'next_action': pb['steps'][0]}

    def advance_step(self, execution_id: str, step_result: str = 'completed') -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        ex = conn.execute('SELECT * FROM playbook_executions WHERE execution_id=?', (execution_id,)).fetchone()
        if not ex:
            conn.close()
            return {'error': 'Execution not found'}
        pb = self.get_playbook(ex['playbook_id'])
        results = json.loads(ex['step_results'])
        results.append({'step': ex['current_step'], 'result': step_result,
                        'timestamp': datetime.now(timezone.utc).isoformat()})
        next_step = ex['current_step'] + 1
        status = 'completed' if next_step > len(pb['steps']) else 'in_progress'
        conn.execute('''UPDATE playbook_executions SET current_step=?, step_results=?, status=?,
                        completed_at=? WHERE execution_id=?''',
                     (next_step, json.dumps(results), status,
                      datetime.now(timezone.utc).isoformat() if status == 'completed' else None, execution_id))
        conn.commit()
        conn.close()
        resp = {'execution_id': execution_id, 'current_step': next_step, 'status': status}
        if status != 'completed':
            resp['next_action'] = pb['steps'][next_step - 1]
        return resp

    def create_custom_playbook(self, name: str, description: str, severity: str,
                               steps: List[Dict], created_by: str = 'admin') -> Dict:
        pid = hashlib.sha256(f"playbook:{name}:{time.time()}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT INTO custom_playbooks
            (playbook_id, name, description, severity, steps, created_at, created_by)
            VALUES (?,?,?,?,?,?,?)''',
            (pid, name, description, severity, json.dumps(steps),
             datetime.now(timezone.utc).isoformat(), created_by))
        conn.commit()
        conn.close()
        return {'playbook_id': pid, 'status': 'created', 'name': name}

    def export_evidence(self, execution_id: str = None, incident_id: str = None) -> Dict:
        """Export evidence bundle as signed JSON."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        if execution_id:
            execs = conn.execute('SELECT * FROM playbook_executions WHERE execution_id=?',
                                 (execution_id,)).fetchall()
        elif incident_id:
            execs = conn.execute('SELECT * FROM playbook_executions WHERE incident_id=?',
                                 (incident_id,)).fetchall()
        else:
            execs = conn.execute('SELECT * FROM playbook_executions ORDER BY started_at DESC LIMIT 10').fetchall()
        conn.close()

        evidence = {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'export_version': '1.0',
            'executions': [dict(e) for e in execs],
        }
        # Sign with SHA-256
        content = json.dumps(evidence, sort_keys=True)
        evidence['integrity_hash'] = hashlib.sha256(content.encode()).hexdigest()

        export_path = os.path.join(self.export_dir, f'evidence_{int(time.time())}.json')
        with open(export_path, 'w') as f:
            json.dump(evidence, f, indent=2)

        return {'export_path': export_path, 'records': len(execs),
                'integrity_hash': evidence['integrity_hash']}

    def get_executions(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM playbook_executions ORDER BY started_at DESC LIMIT ?',
                            (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


_playbook = None
def get_incident_playbook():
    global _playbook
    if _playbook is None:
        _playbook = IncidentPlaybook()
    return _playbook
