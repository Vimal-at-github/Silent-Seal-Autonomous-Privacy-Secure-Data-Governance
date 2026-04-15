"""
SilentSeal - Tamper-Evident Secure Audit Logging
Append-only HMAC-signed hash-chained log for verifiable integrity.
"""
import os, json, hashlib, sqlite3, hmac, time
from typing import Dict, List
from datetime import datetime, timezone


class TamperEvidentAudit:
    """Append-only audit log with HMAC signatures and hash chaining."""

    def __init__(self, db_path=None, secret_key=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'tamper_audit.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.secret_key = (secret_key or 'silentseal-audit-key-change-in-prod').encode()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS audit_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_hash TEXT UNIQUE, prev_hash TEXT,
            event_type TEXT, actor TEXT, resource TEXT,
            action TEXT, details TEXT, hmac_signature TEXT,
            timestamp TEXT)''')
        conn.commit()
        conn.close()

    def _get_last_hash(self, conn) -> str:
        row = conn.execute('SELECT entry_hash FROM audit_chain ORDER BY id DESC LIMIT 1').fetchone()
        return row[0] if row else '0' * 64

    def _compute_hmac(self, data: str) -> str:
        return hmac.new(self.secret_key, data.encode(), hashlib.sha256).hexdigest()

    def log_event(self, event_type: str, actor: str, resource: str = '',
                  action: str = '', details: str = '') -> Dict:
        conn = sqlite3.connect(self.db_path)
        prev_hash = self._get_last_hash(conn)
        ts = datetime.now(timezone.utc).isoformat()
        payload = f"{prev_hash}|{event_type}|{actor}|{resource}|{action}|{details}|{ts}"
        entry_hash = hashlib.sha256(payload.encode()).hexdigest()
        sig = self._compute_hmac(payload)
        conn.execute('''INSERT INTO audit_chain
            (entry_hash, prev_hash, event_type, actor, resource, action, details, hmac_signature, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            (entry_hash, prev_hash, event_type, actor, resource, action, details, sig, ts))
        conn.commit()
        conn.close()
        return {'entry_hash': entry_hash, 'status': 'logged'}

    def verify_integrity(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM audit_chain ORDER BY id ASC').fetchall()
        conn.close()
        if not rows:
            return {'status': 'empty', 'message': 'No log entries'}
        prev = '0' * 64
        broken_at = None
        for i, row in enumerate(rows):
            payload = f"{row['prev_hash']}|{row['event_type']}|{row['actor']}|{row['resource']}|{row['action']}|{row['details']}|{row['timestamp']}"
            expected_hash = hashlib.sha256(payload.encode()).hexdigest()
            expected_sig = self._compute_hmac(payload)
            if row['entry_hash'] != expected_hash or row['hmac_signature'] != expected_sig:
                broken_at = i + 1
                break
            if row['prev_hash'] != prev:
                broken_at = i + 1
                break
            prev = row['entry_hash']
        if broken_at:
            return {'status': 'tampered', 'broken_at_entry': broken_at,
                    'total_entries': len(rows), 'message': f'Chain broken at entry {broken_at}'}
        return {'status': 'verified', 'total_entries': len(rows),
                'message': 'All entries verified — chain intact'}

    def export_log(self, limit: int = 1000) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM audit_chain ORDER BY id ASC LIMIT ?', (limit,)).fetchall()
        conn.close()
        entries = [dict(r) for r in rows]
        content = json.dumps(entries, sort_keys=True)
        return {'entries': entries, 'count': len(entries),
                'export_hash': hashlib.sha256(content.encode()).hexdigest()}

    def get_chain_status(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        total = conn.execute('SELECT COUNT(*) FROM audit_chain').fetchone()[0]
        last = conn.execute('SELECT * FROM audit_chain ORDER BY id DESC LIMIT 1').fetchone()
        conn.close()
        return {'total_entries': total, 'last_hash': last[1] if last else None,
                'status': 'active' if total > 0 else 'empty'}


_tamper_audit = None
def get_tamper_audit():
    global _tamper_audit
    if _tamper_audit is None:
        _tamper_audit = TamperEvidentAudit()
    return _tamper_audit
