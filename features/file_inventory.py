"""
SilentSeal - File Inventory
Risk-based file categorization and dashboard data
"""

import os
import sqlite3
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict


class FileInventory:
    """
    File inventory manager for risk-based categorization.
    
    Features:
    - Group files by risk level (HIGH/MEDIUM/LOW)
    - Dashboard statistics and charts data
    - Entity type breakdown
    - Time-based analytics
    """
    
    def __init__(self, db_path: str = None):
        """Initialize file inventory"""
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "..", "database", "scan_inventory.db"
            )
        
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize inventory database tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scanned_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE,
                file_name TEXT,
                file_size INTEGER,
                file_hash TEXT,
                risk_level TEXT,
                risk_score REAL,
                entities_count INTEGER,
                entity_types TEXT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def add_scanned_file(self, file_path: str, file_name: str, file_size: int, 
                         risk_level: str, risk_score: float, entities_count: int, 
                         entity_types: List[str]):
        """Add or update a scanned file in the inventory"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Simple hash if not provided
        file_hash = hashlib.sha256(file_path.encode()).hexdigest()[:16]
        
        cursor.execute('''
            INSERT OR REPLACE INTO scanned_files 
            (file_path, file_name, file_size, file_hash, risk_level, risk_score, entities_count, entity_types)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (file_path, file_name, file_size, file_hash, risk_level, risk_score, entities_count, ','.join(entity_types)))
        
        conn.commit()
        conn.close()
    
    def get_risk_buckets(self) -> Dict[str, Any]:
        """
        Get files grouped by risk level.
        
        Returns:
            Dictionary with risk buckets and statistics
        """
        if not os.path.exists(self.db_path):
            return self._empty_buckets()
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get counts by risk level
        buckets = {
            "HIGH": {"count": 0, "files": [], "avg_score": 0},
            "MEDIUM": {"count": 0, "files": [], "avg_score": 0},
            "LOW": {"count": 0, "files": [], "avg_score": 0},
            "MINIMAL": {"count": 0, "files": [], "avg_score": 0}
        }
        
        # Also count CRITICAL as HIGH
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN risk_level = 'CRITICAL' THEN 'HIGH'
                    ELSE risk_level 
                END as bucket,
                COUNT(*) as count,
                AVG(risk_score) as avg_score
            FROM scanned_files 
            WHERE entities_count > 0
            GROUP BY bucket
        ''')
        
        for row in cursor.fetchall():
            bucket = row['bucket']
            if bucket in buckets:
                buckets[bucket]["count"] = row['count']
                buckets[bucket]["avg_score"] = round(row['avg_score'], 1) if row['avg_score'] else 0
        
        # Get top files for each bucket
        for level in buckets.keys():
            risk_levels = ['CRITICAL', 'HIGH'] if level == 'HIGH' else [level]
            placeholders = ','.join(['?' for _ in risk_levels])
            
            cursor.execute(f'''
                SELECT file_path, file_name, risk_score, entities_count, entity_types
                FROM scanned_files 
                WHERE risk_level IN ({placeholders})
                ORDER BY risk_score DESC
                LIMIT 20
            ''', risk_levels)
            
            buckets[level]["files"] = [dict(row) for row in cursor.fetchall()]
        
        # Get overall stats
        cursor.execute('SELECT COUNT(*) FROM scanned_files')
        total_files = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM scanned_files WHERE entities_count > 0')
        files_with_pii = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_files_scanned": total_files,
            "files_with_pii": files_with_pii,
            "buckets": buckets,
            "chart_data": self._prepare_chart_data(buckets)
        }
    
    def _empty_buckets(self) -> Dict[str, Any]:
        """Return empty bucket structure"""
        return {
            "total_files_scanned": 0,
            "files_with_pii": 0,
            "buckets": {
                "HIGH": {"count": 0, "files": [], "avg_score": 0},
                "MEDIUM": {"count": 0, "files": [], "avg_score": 0},
                "LOW": {"count": 0, "files": [], "avg_score": 0},
                "MINIMAL": {"count": 0, "files": [], "avg_score": 0}
            },
            "chart_data": {
                "pie": [],
                "bar": []
            }
        }
    
    def _prepare_chart_data(self, buckets: Dict) -> Dict[str, Any]:
        """Prepare data for charts"""
        # Pie chart data
        pie_data = []
        colors = {
            "HIGH": "#ef4444",      # Red
            "MEDIUM": "#f59e0b",    # Amber
            "LOW": "#22c55e",       # Green
            "MINIMAL": "#6b7280"    # Gray
        }
        
        for level, data in buckets.items():
            if data["count"] > 0:
                pie_data.append({
                    "name": level,
                    "value": data["count"],
                    "color": colors.get(level, "#6b7280")
                })
        
        # Bar chart data (same as pie for now)
        bar_data = [
            {"name": level, "count": data["count"], "color": colors.get(level, "#6b7280")}
            for level, data in buckets.items()
        ]
        
        return {
            "pie": pie_data,
            "bar": bar_data
        }
    
    def get_entity_breakdown(self) -> Dict[str, Any]:
        """Get breakdown of detected entity types"""
        if not os.path.exists(self.db_path):
            return {"entities": {}}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT entity_types FROM scanned_files WHERE entities_count > 0')
        
        entity_counts = defaultdict(int)
        
        for row in cursor.fetchall():
            if row[0]:
                for entity_type in row[0].split(','):
                    entity_type = entity_type.strip()
                    if entity_type:
                        entity_counts[entity_type] += 1
        
        conn.close()
        
        # Sort by count
        sorted_entities = sorted(
            entity_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        return {
            "entities": dict(sorted_entities),
            "chart_data": [
                {"name": name, "count": count}
                for name, count in sorted_entities[:10]  # Top 10
            ]
        }
    
    def get_recent_findings(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get most recent files with PII findings"""
        if not os.path.exists(self.db_path):
            return []
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_path, file_name, risk_level, risk_score, 
                   entities_count, entity_types, scan_time
            FROM scanned_files 
            WHERE entities_count > 0
            ORDER BY scan_time DESC
            LIMIT ?
        ''', (limit,))
        
        findings = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return findings
    
    def get_high_risk_files(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get high risk files that need attention"""
        if not os.path.exists(self.db_path):
            return []
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT file_path, file_name, risk_level, risk_score, 
                   entities_count, entity_types, scan_time
            FROM scanned_files 
            WHERE risk_level IN ('CRITICAL', 'HIGH')
            ORDER BY risk_score DESC
            LIMIT ?
        ''', (limit,))
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        # Add recommendation for each file
        for file in files:
            file["recommendation"] = self._get_recommendation(file)
        
        return files
    
    def _get_recommendation(self, file_info: Dict) -> str:
        """Get recommendation for a high-risk file"""
        risk_score = file_info.get("risk_score", 0)
        
        if risk_score >= 80:
            return "ENCRYPT immediately - High re-identification risk"
        elif risk_score >= 60:
            return "Consider encryption or thorough redaction"
        else:
            return "Review and redact sensitive entities"
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get complete dashboard summary data"""
        buckets = self.get_risk_buckets()
        entities = self.get_entity_breakdown()
        recent = self.get_recent_findings(10)
        high_risk = self.get_high_risk_files(10)
        
        return {
            "overview": {
                "total_files": buckets["total_files_scanned"],
                "files_with_pii": buckets["files_with_pii"],
                "high_risk_count": buckets["buckets"]["HIGH"]["count"],
                "medium_risk_count": buckets["buckets"]["MEDIUM"]["count"],
                "low_risk_count": buckets["buckets"]["LOW"]["count"]
            },
            "risk_buckets": buckets,
            "entity_breakdown": entities,
            "recent_findings": recent,
            "high_risk_files": high_risk,
            "charts": {
                "risk_distribution": buckets["chart_data"]["pie"],
                "entity_types": entities["chart_data"]
            }
        }
    
    def search_files(self, query: str = None, risk_level: str = None,
                     entity_type: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search scanned files with filters.
        
        Args:
            query: Search in file name/path
            risk_level: Filter by risk level
            entity_type: Filter by entity type
            limit: Maximum results
            
        Returns:
            List of matching files
        """
        if not os.path.exists(self.db_path):
            return []
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Build query
        sql = "SELECT * FROM scanned_files WHERE 1=1"
        params = []
        
        if query:
            sql += " AND (file_name LIKE ? OR file_path LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])
        
        if risk_level:
            if risk_level == "HIGH":
                sql += " AND risk_level IN ('CRITICAL', 'HIGH')"
            else:
                sql += " AND risk_level = ?"
                params.append(risk_level)
        
        if entity_type:
            sql += " AND entity_types LIKE ?"
            params.append(f"%{entity_type}%")
        
        sql += " ORDER BY scan_time DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(sql, params)
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files
    
    def get_stats_over_time(self, days: int = 30) -> Dict[str, Any]:
        """Get scanning statistics over time"""
        if not os.path.exists(self.db_path):
            return {"daily_stats": []}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get daily scan counts
        cursor.execute('''
            SELECT 
                DATE(scan_time) as date,
                COUNT(*) as files_scanned,
                SUM(CASE WHEN entities_count > 0 THEN 1 ELSE 0 END) as files_with_pii,
                SUM(CASE WHEN risk_level IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END) as high_risk
            FROM scanned_files 
            WHERE scan_time >= DATE('now', '-' || ? || ' days')
            GROUP BY DATE(scan_time)
            ORDER BY date
        ''', (days,))
        
        daily_stats = [
            {
                "date": row[0],
                "files_scanned": row[1],
                "files_with_pii": row[2],
                "high_risk": row[3]
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        
        return {"daily_stats": daily_stats}
    
    def clear_all(self):
        """Clear all scanned files from the inventory database"""
        if not os.path.exists(self.db_path):
            return {"status": "cleared", "message": "No data to clear"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete all records
        cursor.execute('DELETE FROM scanned_files')
        rows_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        return {
            "status": "cleared",
            "message": f"Cleared {rows_deleted} scanned files from inventory"
        }


# Global instance
_file_inventory = None

def get_file_inventory() -> FileInventory:
    """Get or create the global file inventory"""
    global _file_inventory
    if _file_inventory is None:
        _file_inventory = FileInventory()
    return _file_inventory
