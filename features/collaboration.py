"""
SilentSeal - Collaboration Features
Comments on flagged files, task assignment, webhook notifications, activity feed.
"""
import os, json, sqlite3, hashlib, time
from typing import Dict, List, Any, Optional
from datetime import datetime


class CollaborationManager:
    """Team collaboration: comments, task assignment, webhooks, activity feed."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'collaboration.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.webhooks = {}  # name -> url
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            comment_id TEXT UNIQUE, file_path TEXT, author TEXT,
            content TEXT, created_at TEXT, updated_at TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id TEXT UNIQUE, title TEXT, description TEXT,
            file_path TEXT, assigned_to TEXT, assigned_by TEXT,
            status TEXT DEFAULT 'open', priority TEXT DEFAULT 'medium',
            due_date TEXT, created_at TEXT, updated_at TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS activity_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT, actor TEXT, target TEXT,
            details TEXT, timestamp TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS webhook_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE, url TEXT, events TEXT, is_active INTEGER DEFAULT 1)''')
        conn.commit()
        conn.close()

    def add_comment(self, file_path: str, author: str, content: str) -> Dict:
        cid = hashlib.sha256(f"comment:{file_path}:{time.time()}".encode()).hexdigest()[:12]
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute('INSERT INTO comments (comment_id,file_path,author,content,created_at,updated_at) VALUES (?,?,?,?,?,?)',
                     (cid, file_path, author, content, now, now))
        conn.execute('INSERT INTO activity_feed (event_type,actor,target,details,timestamp) VALUES (?,?,?,?,?)',
                     ('comment_added', author, file_path, content[:100], now))
        conn.commit()
        conn.close()
        self._fire_webhook('comment_added', {'file': file_path, 'author': author, 'content': content[:200]})
        return {'comment_id': cid, 'status': 'created'}

    def get_comments(self, file_path: str = None, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        if file_path:
            rows = conn.execute('SELECT * FROM comments WHERE file_path=? ORDER BY created_at DESC LIMIT ?',
                                (file_path, limit)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM comments ORDER BY created_at DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def assign_task(self, title: str, file_path: str, assigned_to: str,
                    assigned_by: str, description: str = '', priority: str = 'medium',
                    due_date: str = None) -> Dict:
        tid = hashlib.sha256(f"task:{title}:{time.time()}".encode()).hexdigest()[:12]
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute('''INSERT INTO tasks (task_id,title,description,file_path,assigned_to,
                        assigned_by,status,priority,due_date,created_at,updated_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                     (tid, title, description, file_path, assigned_to, assigned_by,
                      'open', priority, due_date, now, now))
        conn.execute('INSERT INTO activity_feed (event_type,actor,target,details,timestamp) VALUES (?,?,?,?,?)',
                     ('task_assigned', assigned_by, assigned_to, f'{title} on {os.path.basename(file_path)}', now))
        conn.commit()
        conn.close()
        self._fire_webhook('task_assigned', {'task': title, 'assigned_to': assigned_to, 'file': file_path})
        return {'task_id': tid, 'status': 'created'}

    def update_task_status(self, task_id: str, status: str, updated_by: str = 'system') -> Dict:
        now = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute('UPDATE tasks SET status=?, updated_at=? WHERE task_id=?', (status, now, task_id))
        conn.execute('INSERT INTO activity_feed (event_type,actor,target,details,timestamp) VALUES (?,?,?,?,?)',
                     ('task_updated', updated_by, task_id, f'Status → {status}', now))
        conn.commit()
        conn.close()
        return {'task_id': task_id, 'status': status}

    def get_tasks(self, assigned_to: str = None, status: str = None, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        q = 'SELECT * FROM tasks WHERE 1=1'
        params = []
        if assigned_to:
            q += ' AND assigned_to=?'
            params.append(assigned_to)
        if status:
            q += ' AND status=?'
            params.append(status)
        q += ' ORDER BY created_at DESC LIMIT ?'
        params.append(limit)
        rows = conn.execute(q, params).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def add_webhook(self, name: str, url: str, events: List[str] = None) -> Dict:
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('INSERT INTO webhook_configs (name,url,events) VALUES (?,?,?)',
                         (name, url, json.dumps(events or ['all'])))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.execute('UPDATE webhook_configs SET url=?, events=? WHERE name=?',
                         (url, json.dumps(events or ['all']), name))
            conn.commit()
        conn.close()
        return {'status': 'configured', 'name': name}

    def _fire_webhook(self, event: str, payload: Dict):
        """Fire webhooks (best-effort, non-blocking)."""
        try:
            import urllib.request
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            hooks = conn.execute('SELECT * FROM webhook_configs WHERE is_active=1').fetchall()
            conn.close()
            for hook in hooks:
                events = json.loads(hook['events'])
                if 'all' in events or event in events:
                    data = json.dumps({'event': event, 'payload': payload,
                                       'timestamp': datetime.now().isoformat()}).encode()
                    req = urllib.request.Request(hook['url'], data=data,
                                                 headers={'Content-Type': 'application/json'})
                    try:
                        urllib.request.urlopen(req, timeout=3)
                    except Exception:
                        pass
        except Exception:
            pass

    def get_activity_feed(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute('SELECT * FROM activity_feed ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


_collab = None
def get_collaboration_manager():
    global _collab
    if _collab is None:
        _collab = CollaborationManager()
    return _collab
