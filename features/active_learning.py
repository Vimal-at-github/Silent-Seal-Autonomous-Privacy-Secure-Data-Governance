"""
SilentSeal - Active Learning Loop
Users mark false positives/true positives to auto-adjust detection thresholds.
"""
import os, json, sqlite3, hashlib, time
from typing import Dict, List
from datetime import datetime, timezone
from collections import defaultdict


class ActiveLearning:
    """Active learning: collect feedback, adjust thresholds, reduce false positives."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'active_learning.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feedback_id TEXT UNIQUE, entity_type TEXT, entity_text TEXT,
            rule_name TEXT, is_correct INTEGER, correction_type TEXT,
            context TEXT, submitted_by TEXT, created_at TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS threshold_adjustments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT, original_threshold REAL,
            adjusted_threshold REAL, reason TEXT, adjusted_at TEXT)''')
        conn.commit()
        conn.close()

    def submit_feedback(self, entity_type: str, entity_text: str,
                        is_correct: bool, rule_name: str = '',
                        correction_type: str = '', context: str = '',
                        submitted_by: str = 'user') -> Dict:
        fid = hashlib.sha256(f"fb:{entity_text}:{time.time()}".encode()).hexdigest()[:12]
        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT INTO feedback
            (feedback_id, entity_type, entity_text, rule_name, is_correct,
             correction_type, context, submitted_by, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)''',
            (fid, entity_type, entity_text, rule_name, 1 if is_correct else 0,
             correction_type, context, submitted_by, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        return {'feedback_id': fid, 'status': 'recorded'}

    def get_feedback_stats(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM feedback').fetchall()
        conn.close()
        by_type = defaultdict(lambda: {'total': 0, 'correct': 0, 'incorrect': 0})
        for r in rows:
            t = r['entity_type']
            by_type[t]['total'] += 1
            if r['is_correct']:
                by_type[t]['correct'] += 1
            else:
                by_type[t]['incorrect'] += 1
        for t in by_type:
            total = by_type[t]['total']
            by_type[t]['accuracy'] = round(by_type[t]['correct'] / total, 3) if total else 0
            by_type[t]['fp_rate'] = round(by_type[t]['incorrect'] / total, 3) if total else 0
        return {'total_feedback': len(rows), 'by_entity_type': dict(by_type)}

    def get_adjusted_thresholds(self) -> Dict:
        """Compute adjusted confidence thresholds based on feedback."""
        stats = self.get_feedback_stats()
        adjustments = {}
        for entity_type, data in stats.get('by_entity_type', {}).items():
            if data['total'] < 5:
                continue  # Not enough data
            fp_rate = data['fp_rate']
            if fp_rate > 0.3:
                adjustments[entity_type] = {
                    'recommendation': 'increase_threshold',
                    'reason': f'High FP rate ({fp_rate:.0%})',
                    'suggested_boost': round(min(fp_rate * 0.3, 0.2), 2)
                }
            elif fp_rate < 0.05 and data['total'] >= 10:
                adjustments[entity_type] = {
                    'recommendation': 'decrease_threshold',
                    'reason': f'Very low FP rate ({fp_rate:.0%}), can be more aggressive',
                    'suggested_reduction': 0.05
                }
        return {'adjustments': adjustments, 'based_on': stats['total_feedback']}

    def export_feedback(self, entity_type: str = None) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        if entity_type:
            rows = conn.execute('SELECT * FROM feedback WHERE entity_type=? ORDER BY created_at',
                                (entity_type,)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM feedback ORDER BY created_at').fetchall()
        conn.close()
        return {'count': len(rows), 'feedback': [dict(r) for r in rows]}

    def get_recent_feedback(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM feedback ORDER BY created_at DESC LIMIT ?',
                            (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


_active_learning = None
def get_active_learning():
    global _active_learning
    if _active_learning is None:
        _active_learning = ActiveLearning()
    return _active_learning
