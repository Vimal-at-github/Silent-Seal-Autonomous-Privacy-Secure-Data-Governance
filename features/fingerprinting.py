"""
SilentSeal - Document Fingerprinting
Non-PII fingerprints for duplicate detection, cross-doc linkage, and near-duplicate finding.
"""
import os, json, hashlib, sqlite3, re
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import Counter


class DocumentFingerprinter:
    """Compute non-PII fingerprints for duplicate/near-duplicate detection."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'fingerprints.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doc_id TEXT UNIQUE, file_path TEXT, file_name TEXT,
            content_hash TEXT, simhash TEXT, structure_sig TEXT,
            word_count INTEGER, entity_distribution TEXT,
            created_at TEXT)''')
        conn.commit()
        conn.close()

    def compute_fingerprint(self, doc_id: str, file_path: str, text: str,
                            entities: List[Dict] = None) -> Dict:
        content_hash = hashlib.sha256(text.encode()).hexdigest()
        simhash = self._compute_simhash(text)
        structure = self._compute_structure_sig(text, entities or [])
        entity_dist = {}
        for e in (entities or []):
            t = e.get('type', 'UNKNOWN')
            entity_dist[t] = entity_dist.get(t, 0) + 1

        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT OR REPLACE INTO fingerprints
            (doc_id, file_path, file_name, content_hash, simhash, structure_sig,
             word_count, entity_distribution, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            (doc_id, file_path, os.path.basename(file_path), content_hash,
             simhash, json.dumps(structure), len(text.split()),
             json.dumps(entity_dist), datetime.now().isoformat()))
        conn.commit()
        conn.close()

        return {'doc_id': doc_id, 'content_hash': content_hash,
                'simhash': simhash, 'structure': structure,
                'word_count': len(text.split()), 'entity_distribution': entity_dist}

    def _compute_simhash(self, text: str, hashbits=64) -> str:
        tokens = re.findall(r'\w+', text.lower())
        v = [0] * hashbits
        for t in tokens:
            h = int(hashlib.md5(t.encode()).hexdigest(), 16)
            for i in range(hashbits):
                if h & (1 << i):
                    v[i] += 1
                else:
                    v[i] -= 1
        fingerprint = 0
        for i in range(hashbits):
            if v[i] > 0:
                fingerprint |= (1 << i)
        return format(fingerprint, f'0{hashbits}b')

    def _compute_structure_sig(self, text: str, entities: List[Dict]) -> Dict:
        lines = text.split('\n')
        return {
            'line_count': len(lines),
            'paragraph_count': len([l for l in text.split('\n\n') if l.strip()]),
            'avg_line_length': sum(len(l) for l in lines) / max(len(lines), 1),
            'entity_type_count': len(set(e.get('type', '') for e in entities)),
            'has_numbers': bool(re.search(r'\d{4,}', text)),
            'has_dates': bool(re.search(r'\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}', text)),
        }

    def _hamming_distance(self, a: str, b: str) -> int:
        return sum(c1 != c2 for c1, c2 in zip(a, b))

    def find_duplicates(self, doc_id: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM fingerprints').fetchall()
        conn.close()
        by_hash = {}
        for r in rows:
            by_hash.setdefault(r['content_hash'], []).append(dict(r))
        return [{'content_hash': h, 'count': len(docs),
                 'documents': [{'doc_id': d['doc_id'], 'file_name': d['file_name']} for d in docs]}
                for h, docs in by_hash.items() if len(docs) > 1]

    def find_near_duplicates(self, threshold: int = 5) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM fingerprints').fetchall()
        conn.close()
        pairs = []
        docs = [dict(r) for r in rows]
        for i in range(len(docs)):
            for j in range(i + 1, len(docs)):
                dist = self._hamming_distance(docs[i]['simhash'], docs[j]['simhash'])
                if dist <= threshold:
                    pairs.append({
                        'doc_a': docs[i]['doc_id'], 'doc_b': docs[j]['doc_id'],
                        'file_a': docs[i]['file_name'], 'file_b': docs[j]['file_name'],
                        'hamming_distance': dist,
                        'similarity': round(1 - dist / 64, 3)
                    })
        return sorted(pairs, key=lambda x: x['hamming_distance'])

    def get_fingerprint_db(self, limit=100) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM fingerprints ORDER BY created_at DESC LIMIT ?',
                            (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


_fingerprinter = None
def get_fingerprinter():
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = DocumentFingerprinter()
    return _fingerprinter
