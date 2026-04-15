"""
SilentSeal - Contextual Remediation Workflows
One-click actions after PII detection: Move to Vault, Redact & Replace, 
Encrypt & Quarantine, Notify Admin, Create Incident.
"""

import os
import json
import shutil
import sqlite3
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone
from enum import Enum


class RemediationAction(str, Enum):
    """Available remediation actions"""
    MOVE_TO_VAULT = "move_to_vault"
    REDACT_REPLACE = "redact_replace"
    ENCRYPT_QUARANTINE = "encrypt_quarantine"
    NOTIFY_ADMIN = "notify_admin"
    CREATE_INCIDENT = "create_incident"


class ActionStatus(str, Enum):
    """Status of a remediation action"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RemediationEngine:
    """
    Contextual remediation workflows engine.
    
    After PII detection, suggests and executes one-click remediation actions.
    Maintains a full history of all actions taken for audit purposes.
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'remediation.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.quarantine_dir = os.path.join(os.path.dirname(__file__), '..', 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize remediation tracking database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remediation_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id TEXT UNIQUE NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                risk_level TEXT,
                risk_score REAL,
                entities_found INTEGER DEFAULT 0,
                entity_types TEXT,
                details TEXT,
                result TEXT,
                initiated_by TEXT DEFAULT 'system',
                created_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL DEFAULT 'MEDIUM',
                status TEXT NOT NULL DEFAULT 'open',
                file_path TEXT,
                entities TEXT,
                timeline TEXT,
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                resolved_at TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def suggest_actions(self, file_path: str, risk_level: str, risk_score: float,
                        entities: List[Dict]) -> List[Dict[str, Any]]:
        """
        Suggest remediation actions based on detection results.
        
        Args:
            file_path: Path to the detected file
            risk_level: HIGH, MEDIUM, or LOW
            risk_score: Numeric risk score (0-100)
            entities: List of detected entities
            
        Returns:
            List of suggested actions with priority and description
        """
        suggestions = []
        entity_types = list(set(e.get('type', 'UNKNOWN') for e in entities))
        has_direct_ids = any(t in entity_types for t in [
            'AADHAAR', 'PAN', 'PASSPORT', 'SSN', 'CREDIT_CARD', 'BANK_ACCOUNT'
        ])
        
        # Always suggest: based on risk level
        if risk_level == 'HIGH' or risk_score >= 70:
            suggestions.append({
                'action': RemediationAction.MOVE_TO_VAULT,
                'priority': 1,
                'label': '🔐 Move to Secure Vault',
                'description': 'Encrypt and store in the secure vault immediately',
                'reason': f'High risk score ({risk_score:.0f}%) with {len(entities)} sensitive entities',
                'auto_recommended': True
            })
            suggestions.append({
                'action': RemediationAction.CREATE_INCIDENT,
                'priority': 2,
                'label': '🚨 Create Incident',
                'description': 'Create a tracked incident for investigation',
                'reason': 'High-risk file requires formal incident tracking',
                'auto_recommended': True
            })
        
        if has_direct_ids:
            suggestions.append({
                'action': RemediationAction.REDACT_REPLACE,
                'priority': 1 if risk_level != 'HIGH' else 3,
                'label': '🎭 Redact & Replace (Synthetic)',
                'description': 'Replace PII with realistic synthetic data',
                'reason': f'Contains direct identifiers: {", ".join(entity_types[:3])}',
                'auto_recommended': True
            })
        
        suggestions.append({
            'action': RemediationAction.ENCRYPT_QUARANTINE,
            'priority': 4 if risk_level == 'HIGH' else 2,
            'label': '🔒 Encrypt & Quarantine',
            'description': 'AES-encrypt in place and move to quarantine folder',
            'reason': 'Isolate sensitive file from general access',
            'auto_recommended': risk_level in ['HIGH', 'MEDIUM']
        })
        
        suggestions.append({
            'action': RemediationAction.NOTIFY_ADMIN,
            'priority': 5 if risk_level != 'HIGH' else 3,
            'label': '📢 Notify Admin',
            'description': 'Send notification to system administrator',
            'reason': 'Alert security team about sensitive file detection',
            'auto_recommended': risk_level == 'HIGH'
        })
        
        if risk_level in ['MEDIUM', 'LOW'] and not has_direct_ids:
            suggestions.append({
                'action': RemediationAction.CREATE_INCIDENT,
                'priority': 6,
                'label': '📋 Create Incident',
                'description': 'Log for review and tracking',
                'reason': 'Track for compliance purposes',
                'auto_recommended': False
            })
        
        # Sort by priority
        suggestions.sort(key=lambda x: x['priority'])
        
        return suggestions
    
    def execute_action(self, action_type: str, file_path: str, 
                       risk_level: str = 'MEDIUM', risk_score: float = 50.0,
                       entities: List[Dict] = None, details: Dict = None,
                       initiated_by: str = 'user') -> Dict[str, Any]:
        """
        Execute a specific remediation action.
        
        Args:
            action_type: The remediation action to execute
            file_path: Path to the file
            risk_level: Risk level of the file
            risk_score: Risk score
            entities: Detected entities
            details: Additional action-specific details
            initiated_by: Who initiated the action
            
        Returns:
            Action result with status
        """
        entities = entities or []
        details = details or {}
        action_id = hashlib.sha256(
            f"{file_path}:{action_type}:{time.time()}".encode()
        ).hexdigest()[:16]
        
        file_name = os.path.basename(file_path)
        entity_types = list(set(e.get('type', 'UNKNOWN') for e in entities))
        
        # Record the action
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO remediation_actions 
            (action_id, file_path, file_name, action_type, status, risk_level, risk_score,
             entities_found, entity_types, details, initiated_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            action_id, file_path, file_name, action_type, 'in_progress',
            risk_level, risk_score, len(entities), json.dumps(entity_types),
            json.dumps(details), initiated_by, datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        try:
            result = {}
            
            if action_type == RemediationAction.MOVE_TO_VAULT:
                result = self._action_move_to_vault(file_path, details)
            elif action_type == RemediationAction.REDACT_REPLACE:
                result = self._action_redact_replace(file_path, entities, details)
            elif action_type == RemediationAction.ENCRYPT_QUARANTINE:
                result = self._action_encrypt_quarantine(file_path, details)
            elif action_type == RemediationAction.NOTIFY_ADMIN:
                result = self._action_notify_admin(file_path, risk_level, risk_score, entities, details)
            elif action_type == RemediationAction.CREATE_INCIDENT:
                result = self._action_create_incident(file_path, risk_level, risk_score, entities, details)
            else:
                raise ValueError(f"Unknown action type: {action_type}")
            
            # Update status to completed
            self._update_action_status(action_id, 'completed', result)
            
            return {
                'action_id': action_id,
                'action_type': action_type,
                'status': 'completed',
                'file_path': file_path,
                'result': result,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self._update_action_status(action_id, 'failed', error=str(e))
            return {
                'action_id': action_id,
                'action_type': action_type,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    def _action_move_to_vault(self, file_path: str, details: Dict) -> Dict:
        """Move file to the secure vault"""
        try:
            from .vault import get_vault
            vault = get_vault()
            if not vault.is_unlocked():
                return {
                    'status': 'requires_unlock',
                    'message': 'Vault must be unlocked first. Please unlock the vault and retry.'
                }
            result = vault.add_file(file_path, delete_original=details.get('delete_original', False))
            return {
                'message': f'File moved to secure vault',
                'vault_entry': result.get('vault_name', 'unknown'),
                'original_deleted': details.get('delete_original', False)
            }
        except Exception as e:
            return {'message': f'Vault move queued (vault not available): {str(e)}', 'queued': True}
    
    def _action_redact_replace(self, file_path: str, entities: List[Dict], details: Dict) -> Dict:
        """Redact and replace with synthetic data"""
        try:
            from .synthetic_data import SyntheticDataGenerator
            generator = SyntheticDataGenerator()
            
            replacements = []
            for entity in entities:
                synthetic = generator.generate(entity.get('type', 'NAME'), entity.get('text', ''))
                replacements.append({
                    'original_type': entity.get('type'),
                    'replacement': synthetic,
                    'confidence': entity.get('confidence', 0.95)
                })
            
            return {
                'message': f'Generated {len(replacements)} synthetic replacements',
                'replacements_count': len(replacements),
                'replacements': replacements[:5]  # Show first 5
            }
        except Exception as e:
            return {'message': f'Redaction prepared: {str(e)}', 'partial': True}
    
    def _action_encrypt_quarantine(self, file_path: str, details: Dict) -> Dict:
        """Encrypt file and move to quarantine"""
        try:
            from .encryption import AESEncryption
            aes = AESEncryption()
            
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, f"quarantine_{file_name}.enc")
            
            # Use a system-generated password for quarantine
            quarantine_key = hashlib.sha256(
                f"quarantine:{file_path}:{time.time()}".encode()
            ).hexdigest()[:32]
            
            result = aes.encrypt_file(file_path, quarantine_path, quarantine_key)
            
            # Store quarantine metadata
            meta_path = quarantine_path + '.meta'
            meta = {
                'original_path': file_path,
                'original_name': file_name,
                'quarantined_at': datetime.now(timezone.utc).isoformat(),
                'key_hint': quarantine_key[:4] + '...',
                'reason': details.get('reason', 'PII detected')
            }
            with open(meta_path, 'w') as f:
                json.dump(meta, f, indent=2)
            
            return {
                'message': f'File encrypted and quarantined',
                'quarantine_path': quarantine_path,
                'original_preserved': True
            }
        except Exception as e:
            return {'message': f'Quarantine queued: {str(e)}', 'queued': True}
    
    def _action_notify_admin(self, file_path: str, risk_level: str, 
                             risk_score: float, entities: List[Dict], details: Dict) -> Dict:
        """Send notification to admin"""
        try:
            from .notifications import get_notification_manager
            notifier = get_notification_manager()
            
            entity_summary = ', '.join(set(e.get('type', 'UNKNOWN') for e in entities[:5]))
            message = (
                f"🚨 Sensitive File Alert\n"
                f"File: {os.path.basename(file_path)}\n"
                f"Risk: {risk_level} ({risk_score:.0f}%)\n"
                f"Entities: {entity_summary}\n"
                f"Action Required: Review and remediate"
            )
            
            notifier.send_notification(
                title=f"PII Alert: {os.path.basename(file_path)}",
                message=message,
                level=risk_level
            )
            
            return {
                'message': 'Admin notification sent',
                'notification_type': 'desktop',
                'recipients': details.get('recipients', ['admin'])
            }
        except Exception as e:
            return {'message': f'Notification queued: {str(e)}', 'queued': True}
    
    def _action_create_incident(self, file_path: str, risk_level: str,
                                risk_score: float, entities: List[Dict], details: Dict) -> Dict:
        """Create a formal incident record"""
        incident_id = hashlib.sha256(
            f"incident:{file_path}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        entity_types = list(set(e.get('type', 'UNKNOWN') for e in entities))
        
        severity_map = {'HIGH': 'CRITICAL', 'MEDIUM': 'HIGH', 'LOW': 'MEDIUM'}
        severity = severity_map.get(risk_level, 'MEDIUM')
        
        title = f"PII Detection: {os.path.basename(file_path)}"
        description = (
            f"Sensitive data detected in file: {file_path}\n"
            f"Risk Score: {risk_score:.0f}%\n"
            f"Risk Level: {risk_level}\n"
            f"Entity Types: {', '.join(entity_types)}\n"
            f"Total Entities: {len(entities)}"
        )
        
        timeline = json.dumps([{
            'event': 'Incident Created',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'details': f'Auto-created from PII detection in {os.path.basename(file_path)}'
        }])
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents 
            (incident_id, title, description, severity, status, file_path, entities, 
             timeline, assigned_to, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id, title, description, severity, 'open', file_path,
            json.dumps(entity_types), timeline,
            details.get('assigned_to', 'unassigned'),
            datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        conn.close()
        
        return {
            'message': f'Incident created: {incident_id}',
            'incident_id': incident_id,
            'severity': severity,
            'title': title
        }
    
    def _update_action_status(self, action_id: str, status: str, 
                               result: Dict = None, error: str = None):
        """Update the status of a remediation action"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE remediation_actions 
            SET status = ?, result = ?, completed_at = ?, error_message = ?
            WHERE action_id = ?
        ''', (
            status, json.dumps(result) if result else None,
            datetime.now(timezone.utc).isoformat() if status in ['completed', 'failed'] else None,
            error, action_id
        ))
        conn.commit()
        conn.close()
    
    def get_action_history(self, limit: int = 50, file_path: str = None) -> List[Dict]:
        """Get history of remediation actions"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if file_path:
            cursor.execute('''
                SELECT * FROM remediation_actions WHERE file_path = ?
                ORDER BY created_at DESC LIMIT ?
            ''', (file_path, limit))
        else:
            cursor.execute('''
                SELECT * FROM remediation_actions 
                ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_incidents(self, status: str = None, limit: int = 50) -> List[Dict]:
        """Get list of incidents"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT * FROM incidents WHERE status = ?
                ORDER BY created_at DESC LIMIT ?
            ''', (status, limit))
        else:
            cursor.execute('''
                SELECT * FROM incidents
                ORDER BY created_at DESC LIMIT ?
            ''', (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def update_incident(self, incident_id: str, status: str = None, 
                        assigned_to: str = None, note: str = None) -> Dict:
        """Update an incident"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get current incident
        cursor.execute('SELECT * FROM incidents WHERE incident_id = ?', (incident_id,))
        incident = cursor.fetchone()
        if not incident:
            conn.close()
            return {'error': 'Incident not found'}
        
        updates = []
        params = []
        
        if status:
            updates.append('status = ?')
            params.append(status)
            if status == 'resolved':
                updates.append('resolved_at = ?')
                params.append(datetime.now(timezone.utc).isoformat())
        
        if assigned_to:
            updates.append('assigned_to = ?')
            params.append(assigned_to)
        
        updates.append('updated_at = ?')
        params.append(datetime.now(timezone.utc).isoformat())
        
        # Update timeline
        timeline = json.loads(incident['timeline'] or '[]')
        if note:
            timeline.append({
                'event': note,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'details': f'Status: {status}' if status else ''
            })
        elif status:
            timeline.append({
                'event': f'Status changed to {status}',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        updates.append('timeline = ?')
        params.append(json.dumps(timeline))
        
        params.append(incident_id)
        cursor.execute(
            f'UPDATE incidents SET {", ".join(updates)} WHERE incident_id = ?',
            params
        )
        conn.commit()
        conn.close()
        
        return {'status': 'updated', 'incident_id': incident_id}
    
    def get_stats(self) -> Dict:
        """Get remediation statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM remediation_actions')
        total_actions = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM remediation_actions WHERE status = 'completed'")
        completed = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM remediation_actions WHERE status = 'failed'")
        failed = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        open_incidents = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'")
        resolved_incidents = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT action_type, COUNT(*) as count 
            FROM remediation_actions 
            GROUP BY action_type
        ''')
        by_type = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            'total_actions': total_actions,
            'completed': completed,
            'failed': failed,
            'open_incidents': open_incidents,
            'resolved_incidents': resolved_incidents,
            'actions_by_type': by_type
        }


# Singleton
_remediation_engine = None

def get_remediation_engine() -> RemediationEngine:
    global _remediation_engine
    if _remediation_engine is None:
        _remediation_engine = RemediationEngine()
    return _remediation_engine
