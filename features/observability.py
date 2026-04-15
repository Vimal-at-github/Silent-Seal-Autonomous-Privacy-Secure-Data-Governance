"""
SilentSeal - Observability & SLO Dashboard
Track scan latencies, detection metrics, health status, and SLO compliance.
"""
import os, json, sqlite3, time, platform, psutil
from typing import Dict, List
from datetime import datetime, timedelta, timezone
from collections import defaultdict


class ObservabilityManager:
    """Internal observability: metrics, health, SLOs, admin dashboard."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'observability.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.slo_targets = {
            'scan_latency_p95_ms': 5000,
            'detection_accuracy': 0.90,
            'false_positive_rate': 0.15,
            'uptime_percent': 99.5,
        }
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric_name TEXT, metric_value REAL,
            labels TEXT, timestamp TEXT)''')
        conn.commit()
        conn.close()

    def record_metric(self, name: str, value: float, labels: Dict = None) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.execute('INSERT INTO metrics (metric_name, metric_value, labels, timestamp) VALUES (?,?,?,?)',
                     (name, value, json.dumps(labels or {}), datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()
        return {'status': 'recorded', 'metric': name, 'value': value}

    def get_metrics(self, name: str = None, hours: int = 24, limit: int = 500) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        if name:
            rows = conn.execute(
                'SELECT * FROM metrics WHERE metric_name=? AND timestamp>=? ORDER BY timestamp DESC LIMIT ?',
                (name, since, limit)).fetchall()
        else:
            rows = conn.execute(
                'SELECT * FROM metrics WHERE timestamp>=? ORDER BY timestamp DESC LIMIT ?',
                (since, limit)).fetchall()
        conn.close()
        return {'count': len(rows), 'metrics': [dict(r) for r in rows]}

    def get_health(self) -> Dict:
        try:
            cpu = psutil.cpu_percent(interval=0.5)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage(os.path.dirname(self.db_path))
            return {
                'status': 'healthy',
                'system': {
                    'platform': platform.system(),
                    'cpu_percent': cpu,
                    'memory_used_gb': round(mem.used / (1024**3), 2),
                    'memory_total_gb': round(mem.total / (1024**3), 2),
                    'memory_percent': mem.percent,
                    'disk_used_gb': round(disk.used / (1024**3), 2),
                    'disk_total_gb': round(disk.total / (1024**3), 2),
                    'disk_percent': round(disk.used / disk.total * 100, 1),
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return {'status': 'degraded', 'error': str(e),
                    'timestamp': datetime.now(timezone.utc).isoformat()}

    def get_slo_status(self) -> Dict:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        slo_results = {}

        # Scan latency P95
        rows = conn.execute(
            "SELECT metric_value FROM metrics WHERE metric_name='scan_latency_ms' AND timestamp>=? ORDER BY metric_value",
            (since,)).fetchall()
        if rows:
            values = [r['metric_value'] for r in rows]
            p95_idx = int(len(values) * 0.95)
            p95 = values[min(p95_idx, len(values) - 1)]
            target = self.slo_targets['scan_latency_p95_ms']
            slo_results['scan_latency_p95'] = {
                'current': round(p95, 1), 'target': target,
                'met': p95 <= target, 'unit': 'ms'
            }

        # FP rate
        rows = conn.execute(
            "SELECT metric_value FROM metrics WHERE metric_name='false_positive_rate' AND timestamp>=?",
            (since,)).fetchall()
        if rows:
            avg_fp = sum(r['metric_value'] for r in rows) / len(rows)
            target = self.slo_targets['false_positive_rate']
            slo_results['false_positive_rate'] = {
                'current': round(avg_fp, 3), 'target': target,
                'met': avg_fp <= target
            }

        conn.close()
        met = sum(1 for s in slo_results.values() if s.get('met', True))
        return {'slos': slo_results, 'slos_met': met,
                'slos_total': len(slo_results), 'period': '24h'}

    def get_dashboard(self) -> Dict:
        health = self.get_health()
        slos = self.get_slo_status()
        conn = sqlite3.connect(self.db_path)
        total = conn.execute('SELECT COUNT(*) FROM metrics').fetchone()[0]

        # Recent metric summary
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        rows = conn.execute(
            'SELECT metric_name, COUNT(*) as cnt, AVG(metric_value) as avg_val FROM metrics WHERE timestamp>=? GROUP BY metric_name',
            (since,)).fetchall()
        conn.close()
        metric_summary = {r[0]: {'count': r[1], 'avg': round(r[2], 2)} for r in rows}

        return {'health': health, 'slo_status': slos,
                'total_metrics_recorded': total,
                'metric_summary_24h': metric_summary,
                'timestamp': datetime.now(timezone.utc).isoformat()}


_observability = None
def get_observability():
    global _observability
    if _observability is None:
        _observability = ObservabilityManager()
    return _observability
