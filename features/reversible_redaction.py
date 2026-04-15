"""
SilentSeal - Selective Reversible Redaction
Redact for sharing but allow auditable key release or time-limited token access.
"""
import os, json, hashlib, secrets, sqlite3, time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone


class ReversibleRedaction:
    """Reversible redaction with time-limited tokens and audit trail."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'reversible.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS redacted_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            redaction_id TEXT UNIQUE, doc_id TEXT, entity_index INTEGER,
            entity_type TEXT, original_value_encrypted TEXT,
            replacement_text TEXT, encryption_key_hash TEXT,
            created_at TEXT, created_by TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS access_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE, redaction_id TEXT, granted_to TEXT,
            reason TEXT, expires_at TEXT, is_revoked INTEGER DEFAULT 0,
            created_at TEXT, created_by TEXT,
            FOREIGN KEY (redaction_id) REFERENCES redacted_items(redaction_id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS reveal_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            redaction_id TEXT, token TEXT, revealed_by TEXT,
            result TEXT, timestamp TEXT)''')
        conn.commit()
        conn.close()

    def redact_reversible(self, doc_id: str, entities: List[Dict],
                          created_by: str = 'system') -> Dict:
        """Redact entities but store encrypted originals for possible reversal."""
        conn = sqlite3.connect(self.db_path)
        redaction_ids = []
        for i, entity in enumerate(entities):
            rid = hashlib.sha256(f"{doc_id}:{i}:{time.time()}".encode()).hexdigest()[:16]
            key = secrets.token_hex(32)
            # Simple XOR-based obfuscation of original value
            original = entity.get('text', '')
            encrypted = self._simple_encrypt(original, key)
            replacement = entity.get('replacement', f'[REDACTED-{entity.get("type", "PII")}]')
            conn.execute('''INSERT INTO redacted_items
                (redaction_id, doc_id, entity_index, entity_type,
                 original_value_encrypted, replacement_text,
                 encryption_key_hash, created_at, created_by)
                VALUES (?,?,?,?,?,?,?,?,?)''',
                (rid, doc_id, i, entity.get('type', 'UNKNOWN'),
                 encrypted, replacement, hashlib.sha256(key.encode()).hexdigest(),
                 datetime.now(timezone.utc).isoformat(), created_by))
            redaction_ids.append({'redaction_id': rid, 'entity_type': entity.get('type'),
                                  'replacement': replacement, '_key': key})
        conn.commit()
        conn.close()
        return {'doc_id': doc_id, 'redactions_count': len(redaction_ids),
                'redaction_ids': redaction_ids,
                'note': 'Store _key values securely — needed for reveal'}

    def _simple_encrypt(self, text: str, key: str) -> str:
        key_bytes = key.encode()
        encrypted = bytes([b ^ key_bytes[i % len(key_bytes)]
                           for i, b in enumerate(text.encode())])
        import base64
        return base64.b64encode(encrypted).decode()

    def _simple_decrypt(self, encrypted: str, key: str) -> str:
        import base64
        data = base64.b64decode(encrypted)
        key_bytes = key.encode()
        return bytes([b ^ key_bytes[i % len(key_bytes)]
                      for i, b in enumerate(data)]).decode()

    def generate_access_token(self, redaction_id: str, granted_to: str,
                              reason: str, hours_valid: int = 24,
                              created_by: str = 'admin') -> Dict:
        """Generate a time-limited access token for revealing redacted content."""
        token = secrets.token_urlsafe(32)
        expires = (datetime.now() + timedelta(hours=hours_valid)).isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT INTO access_tokens
            (token, redaction_id, granted_to, reason, expires_at, created_at, created_by)
            VALUES (?,?,?,?,?,?,?)''',
            (token, redaction_id, granted_to, reason, expires,
             datetime.now(timezone.utc).isoformat(), created_by))
        conn.commit()
        conn.close()
        return {'token': token, 'redaction_id': redaction_id,
                'expires_at': expires, 'granted_to': granted_to}

    def reveal_with_token(self, token: str, key: str, revealed_by: str) -> Dict:
        """Reveal redacted content using a valid token and decryption key."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        tok = conn.execute('SELECT * FROM access_tokens WHERE token = ?', (token,)).fetchone()
        if not tok:
            conn.close()
            return {'error': 'Invalid token'}
        if tok['is_revoked']:
            self._log_reveal(conn, tok['redaction_id'], token, revealed_by, 'denied_revoked')
            conn.close()
            return {'error': 'Token has been revoked'}
        if datetime.fromisoformat(tok['expires_at']) < datetime.now():
            self._log_reveal(conn, tok['redaction_id'], token, revealed_by, 'denied_expired')
            conn.close()
            return {'error': 'Token has expired'}

        item = conn.execute('SELECT * FROM redacted_items WHERE redaction_id = ?',
                            (tok['redaction_id'],)).fetchone()
        if not item:
            conn.close()
            return {'error': 'Redaction not found'}

        key_hash = hashlib.sha256(key.encode()).hexdigest()
        if key_hash != item['encryption_key_hash']:
            self._log_reveal(conn, tok['redaction_id'], token, revealed_by, 'denied_wrong_key')
            conn.close()
            return {'error': 'Invalid decryption key'}

        original = self._simple_decrypt(item['original_value_encrypted'], key)
        self._log_reveal(conn, tok['redaction_id'], token, revealed_by, 'success')
        conn.close()
        return {'original_value': original, 'entity_type': item['entity_type'],
                'redaction_id': tok['redaction_id']}

    def _log_reveal(self, conn, redaction_id, token, revealed_by, result):
        conn.execute('''INSERT INTO reveal_log (redaction_id, token, revealed_by, result, timestamp)
            VALUES (?,?,?,?,?)''', (redaction_id, token, revealed_by, result,
                                     datetime.now(timezone.utc).isoformat()))
        conn.commit()

    def revoke_token(self, token: str) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE access_tokens SET is_revoked = 1 WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        return {'status': 'revoked', 'token': token[:8] + '...'}

    def get_reveal_log(self, redaction_id=None, limit=100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        if redaction_id:
            rows = conn.execute('SELECT * FROM reveal_log WHERE redaction_id = ? ORDER BY timestamp DESC LIMIT ?',
                                (redaction_id, limit)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM reveal_log ORDER BY timestamp DESC LIMIT ?',
                                (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_redaction_info(self, doc_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT redaction_id, doc_id, entity_index, entity_type, replacement_text, created_at FROM redacted_items WHERE doc_id = ?',
                            (doc_id,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


_reversible = None
def get_reversible_redaction():
    global _reversible
    if _reversible is None:
        _reversible = ReversibleRedaction()
    return _reversible
