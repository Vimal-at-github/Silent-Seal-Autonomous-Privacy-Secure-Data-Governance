"""
SilentSeal - Audit Logger
Maintains comprehensive audit trail for compliance
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import hashlib


class AuditLogger:
    """
    Audit logging system for SilentSeal
    - Records all document processing events
    - Maintains SHA-256 hashes for integrity verification
    - Supports GDPR/HIPAA compliance requirements
    """
    
    def __init__(self, db_path: str = None):
        """Initialize audit logger with SQLite database"""
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "..", "database", "audit.db")
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Document uploads table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS document_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_size INTEGER,
                doc_hash TEXT,
                upload_time TEXT NOT NULL,
                status TEXT DEFAULT 'uploaded'
            )
        ''')
        
        # Processing events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processing_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (doc_id) REFERENCES document_uploads(doc_id)
            )
        ''')
        
        # Entity detections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entity_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_hash TEXT NOT NULL,
                confidence REAL,
                detection_method TEXT,
                page_number INTEGER,
                coordinates TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (doc_id) REFERENCES document_uploads(doc_id)
            )
        ''')
        
        # Risk assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT NOT NULL,
                risk_score REAL,
                risk_level TEXT,
                quasi_identifiers TEXT,
                k_anonymity INTEGER,
                recommendations TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (doc_id) REFERENCES document_uploads(doc_id)
            )
        ''')
        
        # Redaction actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS redaction_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                doc_id TEXT NOT NULL,
                original_hash TEXT,
                redacted_hash TEXT,
                entities_redacted INTEGER,
                pages_affected INTEGER,
                synthetic_replacements INTEGER DEFAULT 0,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (doc_id) REFERENCES document_uploads(doc_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_upload(self, doc_id: str, filename: str, file_size: int, doc_hash: str = None):
        """Log a document upload event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO document_uploads (doc_id, filename, file_size, doc_hash, upload_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (doc_id, filename, file_size, doc_hash, datetime.now(timezone.utc).isoformat()))
        
        self._log_event(cursor, doc_id, "UPLOAD", {
            "filename": filename,
            "file_size": file_size
        })
        
        conn.commit()
        conn.close()
    
    def log_processing(self, doc_id: str, entities: List[Dict], risk_result: Dict):
        """Log document processing including entity detection and risk assessment"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Log each detected entity (hash the actual values for privacy)
        for entity in entities:
            entity_hash = hashlib.sha256(entity.get("text", "").encode()).hexdigest()[:16]
            
            cursor.execute('''
                INSERT INTO entity_detections 
                (doc_id, entity_type, entity_hash, confidence, detection_method, coordinates, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                doc_id,
                entity.get("type"),
                entity_hash,
                entity.get("confidence"),
                entity.get("method"),
                json.dumps(entity.get("coordinates")),
                datetime.now(timezone.utc).isoformat()
            ))
        
        # Log risk assessment
        cursor.execute('''
            INSERT INTO risk_assessments 
            (doc_id, risk_score, risk_level, quasi_identifiers, k_anonymity, recommendations, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            doc_id,
            risk_result.get("score"),
            risk_result.get("level"),
            json.dumps(risk_result.get("quasi_identifiers", [])),
            risk_result.get("k_anonymity"),
            json.dumps(risk_result.get("recommendations", [])),
            datetime.now(timezone.utc).isoformat()
        ))
        
        self._log_event(cursor, doc_id, "PROCESSING_COMPLETE", {
            "entities_found": len(entities),
            "risk_score": risk_result.get("score")
        })
        
        conn.commit()
        conn.close()
    
    def log_redaction(self, doc_id: str, original_hash: str, redacted_hash: str, 
                      entities_redacted: int, pages_affected: int, synthetic_count: int = 0):
        """Log a redaction action"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO redaction_actions 
            (doc_id, original_hash, redacted_hash, entities_redacted, pages_affected, synthetic_replacements, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (doc_id, original_hash, redacted_hash, entities_redacted, pages_affected, synthetic_count, datetime.now(timezone.utc).isoformat()))
        
        self._log_event(cursor, doc_id, "REDACTION_APPLIED", {
            "entities_redacted": entities_redacted,
            "pages_affected": pages_affected,
            "synthetic_replacements": synthetic_count
        })
        
        # Update document status
        cursor.execute('''
            UPDATE document_uploads SET status = 'redacted' WHERE doc_id = ?
        ''', (doc_id,))
        
        conn.commit()
        conn.close()
    
    def _log_event(self, cursor, doc_id: str, event_type: str, event_data: Dict):
        """Log a generic event"""
        cursor.execute('''
            INSERT INTO processing_events (doc_id, event_type, event_data, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (doc_id, event_type, json.dumps(event_data), datetime.now(timezone.utc).isoformat()))
    
    def get_logs(self, doc_id: str) -> Dict[str, Any]:
        """Get all audit logs for a document"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get document info
        cursor.execute('SELECT * FROM document_uploads WHERE doc_id = ?', (doc_id,))
        doc_row = cursor.fetchone()
        
        if not doc_row:
            conn.close()
            return {"error": "Document not found"}
        
        document_info = dict(doc_row)
        
        # Get processing events
        cursor.execute('''
            SELECT event_type, event_data, timestamp 
            FROM processing_events 
            WHERE doc_id = ? 
            ORDER BY timestamp
        ''', (doc_id,))
        events = [dict(row) for row in cursor.fetchall()]
        
        # Get entity detection summary (not actual values for privacy)
        cursor.execute('''
            SELECT entity_type, COUNT(*) as count, AVG(confidence) as avg_confidence
            FROM entity_detections 
            WHERE doc_id = ?
            GROUP BY entity_type
        ''', (doc_id,))
        entity_summary = [dict(row) for row in cursor.fetchall()]
        
        # Get risk assessment
        cursor.execute('''
            SELECT risk_score, risk_level, k_anonymity, recommendations, timestamp
            FROM risk_assessments 
            WHERE doc_id = ?
            ORDER BY timestamp DESC
            LIMIT 1
        ''', (doc_id,))
        risk_row = cursor.fetchone()
        risk_assessment = dict(risk_row) if risk_row else None
        
        conn.close()
        
        return {
            "document": document_info,
            "events": events,
            "entity_summary": entity_summary,
            "risk_assessment": risk_assessment
        }
    
    def get_all_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all audit logs across all documents"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT e.event_type, e.event_data, e.timestamp, u.filename as file_name
            FROM processing_events e
            JOIN document_uploads u ON e.doc_id = u.doc_id
            ORDER BY e.timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        logs = []
        for row in cursor.fetchall():
            log = dict(row)
            # Map database field names to what the frontend expects
            log['action_type'] = log.pop('event_type')
            log['details'] = log.pop('event_data')
            logs.append(log)
            
        conn.close()
        return logs

    def clear_logs(self):
        """Clear all audit logs from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM processing_events')
        cursor.execute('DELETE FROM entity_detections')
        cursor.execute('DELETE FROM risk_assessments')
        cursor.execute('DELETE FROM redaction_actions')
        cursor.execute('DELETE FROM document_uploads')
        
        conn.commit()
        conn.close()
        return {"status": "success", "message": "All audit logs cleared"}

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall system statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total documents processed
        cursor.execute('SELECT COUNT(*) FROM document_uploads')
        stats["total_documents"] = cursor.fetchone()[0]
        
        # Total entities detected
        cursor.execute('SELECT COUNT(*) FROM entity_detections')
        stats["total_entities_detected"] = cursor.fetchone()[0]
        
        # Entity type breakdown
        cursor.execute('''
            SELECT entity_type, COUNT(*) as count 
            FROM entity_detections 
            GROUP BY entity_type
            ORDER BY count DESC
        ''')
        stats["entity_breakdown"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Average risk score
        cursor.execute('SELECT AVG(risk_score) FROM risk_assessments')
        avg_risk = cursor.fetchone()[0]
        stats["average_risk_score"] = round(avg_risk, 2) if avg_risk else 0
        
        # Documents by status
        cursor.execute('''
            SELECT status, COUNT(*) as count 
            FROM document_uploads 
            GROUP BY status
        ''')
        stats["documents_by_status"] = {row[0]: row[1] for row in cursor.fetchall()}
        
        conn.close()
        
        return stats
    
    def export_audit_report(self, doc_id: str, output_path: str):
        """Export a detailed audit report for compliance purposes"""
        logs = self.get_logs(doc_id)
        
        report = {
            "report_generated": datetime.now().isoformat(),
            "document_id": doc_id,
            "audit_trail": logs,
            "compliance_statement": (
                "This audit report provides a complete record of all processing "
                "activities performed on the document. Entity values have been "
                "hashed to prevent exposure of sensitive data in audit logs. "
                "SHA-256 document hashes enable integrity verification."
            )
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return output_path

    def clear_logs(self):
        """Clear all audit logs from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM processing_events')
        cursor.execute('DELETE FROM entity_detections')
        cursor.execute('DELETE FROM risk_assessments')
        cursor.execute('DELETE FROM redaction_actions')
        cursor.execute('DELETE FROM document_uploads')
        
        conn.commit()
        conn.close()
        return {"status": "success", "message": "All audit logs cleared"}


# Global instance
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Get or create the global audit logger"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
