"""
SilentSeal - Granular RBAC & Approval Flows
Multi-user support, approval chains, and per-access audit trail.
"""

import os
import json
import sqlite3
import hashlib
import secrets
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from enum import Enum


class Role(str, Enum):
    """User roles with increasing privileges"""
    VIEWER = "viewer"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    ADMIN = "admin"


class Permission(str, Enum):
    """Granular permissions"""
    VIEW_DOCUMENTS = "view_documents"
    UPLOAD_DOCUMENTS = "upload_documents"
    REDACT_DOCUMENTS = "redact_documents"
    VIEW_VAULT = "view_vault"
    MANAGE_VAULT = "manage_vault"
    DECRYPT_FILES = "decrypt_files"
    VIEW_AUDIT = "view_audit"
    MANAGE_USERS = "manage_users"
    APPROVE_REQUESTS = "approve_requests"
    EXPORT_DATA = "export_data"
    VIEW_ANALYTICS = "view_analytics"
    MANAGE_SETTINGS = "manage_settings"
    CREATE_INCIDENTS = "create_incidents"
    MANAGE_INCIDENTS = "manage_incidents"
    REVEAL_REDACTED = "reveal_redacted"


# Role → permissions mapping
ROLE_PERMISSIONS = {
    Role.VIEWER: [
        Permission.VIEW_DOCUMENTS,
        Permission.VIEW_AUDIT,
    ],
    Role.ANALYST: [
        Permission.VIEW_DOCUMENTS,
        Permission.UPLOAD_DOCUMENTS,
        Permission.REDACT_DOCUMENTS,
        Permission.VIEW_VAULT,
        Permission.VIEW_AUDIT,
        Permission.VIEW_ANALYTICS,
        Permission.CREATE_INCIDENTS,
    ],
    Role.AUDITOR: [
        Permission.VIEW_DOCUMENTS,
        Permission.VIEW_VAULT,
        Permission.VIEW_AUDIT,
        Permission.VIEW_ANALYTICS,
        Permission.EXPORT_DATA,
    ],
    Role.ADMIN: list(Permission),  # All permissions
}


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class RBACManager:
    """
    Role-Based Access Control with approval chains.
    
    Features:
    - User management with hashed passwords
    - Role-based permissions
    - Approval workflows for sensitive operations (decrypt, reveal)
    - Complete access audit trail
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'rbac.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_database()
        self._ensure_default_admin()
    
    def _init_database(self):
        """Initialize RBAC database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                display_name TEXT,
                email TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login TEXT,
                created_by TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                FOREIGN KEY (username) REFERENCES users(username)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS approval_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT UNIQUE NOT NULL,
                requested_by TEXT NOT NULL,
                action_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                justification TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                reviewed_by TEXT,
                review_note TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                expires_at TEXT,
                FOREIGN KEY (requested_by) REFERENCES users(username)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT,
                result TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                timestamp TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _ensure_default_admin(self):
        """Create default admin if no users exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        conn.close()
        
        if count == 0:
            self.create_user('admin', 'admin123', Role.ADMIN, 
                           display_name='System Administrator',
                           created_by='system')
    
    def _hash_password(self, password: str, salt: str = None) -> tuple:
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = secrets.token_hex(32)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), salt.encode(), 100000
        ).hex()
        return password_hash, salt
    
    def create_user(self, username: str, password: str, role: str = Role.VIEWER,
                    display_name: str = None, email: str = None,
                    created_by: str = 'admin') -> Dict[str, Any]:
        """Create a new user"""
        password_hash, salt = self._hash_password(password)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, salt, role, display_name, 
                                   email, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                username, password_hash, salt, role,
                display_name or username, email,
                datetime.now(timezone.utc).isoformat(), created_by
            ))
            conn.commit()
            
            self._log_access(created_by, 'create_user', username, 'success',
                           f'Created user {username} with role {role}')
            
            return {
                'status': 'created',
                'username': username,
                'role': role,
                'display_name': display_name or username
            }
        except sqlite3.IntegrityError:
            return {'status': 'error', 'message': f'User {username} already exists'}
        finally:
            conn.close()
    
    def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user and create session"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()
        
        if not user:
            self._log_access(username, 'login', None, 'failed', 'User not found or inactive')
            conn.close()
            return {'status': 'error', 'message': 'Invalid credentials'}
        
        password_hash, _ = self._hash_password(password, user['salt'])
        
        if password_hash != user['password_hash']:
            self._log_access(username, 'login', None, 'failed', 'Invalid password')
            conn.close()
            return {'status': 'error', 'message': 'Invalid credentials'}
        
        # Create session token
        session_token = secrets.token_hex(32)
        expires_at = (datetime.now() + timedelta(hours=24)).isoformat()
        
        cursor.execute('''
            INSERT INTO sessions (session_token, username, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (session_token, username, datetime.now(timezone.utc).isoformat(), expires_at))
        
        # Update last login
        cursor.execute(
            'UPDATE users SET last_login = ? WHERE username = ?',
            (datetime.now(timezone.utc).isoformat(), username)
        )
        
        conn.commit()
        conn.close()
        
        self._log_access(username, 'login', None, 'success', 'Session created')
        
        return {
            'status': 'authenticated',
            'session_token': session_token,
            'username': username,
            'role': user['role'],
            'display_name': user['display_name'],
            'expires_at': expires_at
        }
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate a session token and return user info"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.*, u.role, u.display_name, u.email 
            FROM sessions s JOIN users u ON s.username = u.username
            WHERE s.session_token = ? AND s.is_active = 1
        ''', (session_token,))
        
        session = cursor.fetchone()
        conn.close()
        
        if not session:
            return None
        
        if datetime.fromisoformat(session['expires_at']) < datetime.now():
            self.logout(session_token)
            return None
        
        return {
            'username': session['username'],
            'role': session['role'],
            'display_name': session['display_name'],
            'email': session['email']
        }
    
    def logout(self, session_token: str) -> Dict:
        """Invalidate a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE sessions SET is_active = 0 WHERE session_token = ?',
            (session_token,)
        )
        conn.commit()
        conn.close()
        return {'status': 'logged_out'}
    
    def check_permission(self, username: str, permission: str) -> bool:
        """Check if a user has a specific permission"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT role FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return False
        
        role = user['role']
        role_perms = ROLE_PERMISSIONS.get(role, [])
        return permission in role_perms
    
    def request_approval(self, requested_by: str, action_type: str,
                        resource: str, justification: str = None) -> Dict:
        """Create an approval request for sensitive operations"""
        request_id = hashlib.sha256(
            f"approval:{requested_by}:{action_type}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = (datetime.now() + timedelta(hours=48)).isoformat()
        
        cursor.execute('''
            INSERT INTO approval_requests 
            (request_id, requested_by, action_type, resource, justification,
             status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            request_id, requested_by, action_type, resource,
            justification, 'pending', datetime.now(timezone.utc).isoformat(), expires_at
        ))
        conn.commit()
        conn.close()
        
        self._log_access(requested_by, 'request_approval', resource, 'pending',
                        f'Approval requested for {action_type}')
        
        return {
            'request_id': request_id,
            'status': 'pending',
            'action_type': action_type,
            'resource': resource,
            'expires_at': expires_at
        }
    
    def approve_request(self, request_id: str, reviewed_by: str, 
                       approved: bool, note: str = None) -> Dict:
        """Approve or deny a pending request"""
        if not self.check_permission(reviewed_by, Permission.APPROVE_REQUESTS):
            return {'status': 'error', 'message': 'Insufficient permissions'}
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM approval_requests WHERE request_id = ?', (request_id,))
        request = cursor.fetchone()
        
        if not request:
            conn.close()
            return {'status': 'error', 'message': 'Request not found'}
        
        if request['status'] != 'pending':
            conn.close()
            return {'status': 'error', 'message': f'Request already {request["status"]}'}
        
        new_status = 'approved' if approved else 'denied'
        
        cursor.execute('''
            UPDATE approval_requests 
            SET status = ?, reviewed_by = ?, review_note = ?, reviewed_at = ?
            WHERE request_id = ?
        ''', (new_status, reviewed_by, note, datetime.now(timezone.utc).isoformat(), request_id))
        
        conn.commit()
        conn.close()
        
        self._log_access(reviewed_by, f'{new_status}_request', request['resource'],
                        'success', f'Request {request_id} {new_status}')
        
        return {
            'request_id': request_id,
            'status': new_status,
            'reviewed_by': reviewed_by,
            'note': note
        }
    
    def get_pending_approvals(self, limit: int = 50) -> List[Dict]:
        """Get all pending approval requests"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM approval_requests WHERE status = 'pending'
            ORDER BY created_at DESC LIMIT ?
        ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def get_access_log(self, username: str = None, limit: int = 100) -> List[Dict]:
        """Get access audit log"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if username:
            cursor.execute('''
                SELECT * FROM access_log WHERE username = ?
                ORDER BY timestamp DESC LIMIT ?
            ''', (username, limit))
        else:
            cursor.execute('''
                SELECT * FROM access_log
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def list_users(self) -> List[Dict]:
        """List all users (without sensitive fields)"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT username, role, display_name, email, is_active, 
                   created_at, last_login, created_by
            FROM users ORDER BY created_at
        ''')
        
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
    
    def update_user_role(self, username: str, new_role: str, updated_by: str) -> Dict:
        """Update a user's role"""
        if not self.check_permission(updated_by, Permission.MANAGE_USERS):
            return {'status': 'error', 'message': 'Insufficient permissions'}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET role = ? WHERE username = ?',
            (new_role, username)
        )
        conn.commit()
        conn.close()
        
        self._log_access(updated_by, 'update_role', username, 'success',
                        f'Role changed to {new_role}')
        
        return {'status': 'updated', 'username': username, 'new_role': new_role}
    
    def deactivate_user(self, username: str, deactivated_by: str) -> Dict:
        """Deactivate a user account"""
        if username == 'admin':
            return {'status': 'error', 'message': 'Cannot deactivate default admin'}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_active = 0 WHERE username = ?', (username,))
        cursor.execute('UPDATE sessions SET is_active = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        
        self._log_access(deactivated_by, 'deactivate_user', username, 'success')
        return {'status': 'deactivated', 'username': username}
    
    def _log_access(self, username: str, action: str, resource: str = None,
                    result: str = 'success', details: str = None):
        """Log an access event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO access_log (username, action, resource, result, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, action, resource, result, details, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        conn.close()


# Singleton
_rbac_manager = None

def get_rbac_manager() -> RBACManager:
    global _rbac_manager
    if _rbac_manager is None:
        _rbac_manager = RBACManager()
    return _rbac_manager
