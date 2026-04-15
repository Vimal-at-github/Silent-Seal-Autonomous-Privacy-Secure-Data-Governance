"""
SilentSeal - Privacy Graph
Data Relationship Mapping & Re-identification Risk Analysis
"""

import os
import sqlite3
import json
import hashlib
from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timezone

class PrivacyGraph:
    """
    Analyzes relationships between data entities based on co-occurrence in files.
    Helps identify re-identification chains and data linkage risks.
    """
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(__file__), "..", "database", "privacy_graph.db"
            )
        
        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize graph database tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Entities table (unique identities based on hash)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS graph_entities (
                entity_hash TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                sample_text TEXT, -- Optional, for UI labels if privacy settings allow
                last_seen TEXT NOT NULL
            )
        ''')
        
        # Occurrences table (entity -> document mapping)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entity_occurrences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_hash TEXT NOT NULL,
                doc_id TEXT NOT NULL,
                file_name TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (entity_hash) REFERENCES graph_entities(entity_hash)
            )
        ''')
        
        # Risk chains table (pre-calculated or flagged risks)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT UNIQUE,
                entities TEXT, -- JSON list of entity hashes
                risk_level TEXT,
                description TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        
        conn.commit()
        conn.close()

    def add_finding(self, doc_id: str, file_name: str, entities: List[Dict]):
        """
        Record entity occurrences and update graph relationships.
        
        Args:
            doc_id: Unique document identifier
            file_name: Name of the file
            entities: List of detected entities {text, type, hash}
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        for entity in entities:
            # We use the hash provided during processing (standardized in audit/main)
            e_text = entity.get("text", "")
            e_type = entity.get("type", "UNKNOWN")
            
            # Use consistent hashing if not provided
            e_hash = entity.get("hash") or hashlib.sha256(e_text.encode()).hexdigest()[:16]
            
            # 1. Update/Insert Entity
            cursor.execute('''
                INSERT INTO graph_entities (entity_hash, entity_type, sample_text, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(entity_hash) DO UPDATE SET 
                    last_seen = excluded.last_seen,
                    sample_text = CASE WHEN sample_text IS NULL THEN excluded.sample_text ELSE sample_text END
            ''', (e_hash, e_type, e_text[:32], now)) # Truncate sample text for safety
            
            # 2. Record Occurrence (avoid duplicates for same doc)
            cursor.execute('''
                INSERT INTO entity_occurrences (entity_hash, doc_id, file_name, timestamp)
                SELECT ?, ?, ?, ?
                WHERE NOT EXISTS (
                    SELECT 1 FROM entity_occurrences WHERE entity_hash = ? AND doc_id = ?
                )
            ''', (e_hash, doc_id, file_name, now, e_hash, doc_id))
            
        conn.commit()
        conn.close()
        
        # Potentially trigger risk analysis here in a real app
        # For now we do it on demand

    def get_documents(self) -> List[Dict]:
        """Get list of all documents in the graph"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT doc_id, file_name, COUNT(entity_hash) as entity_count, timestamp
            FROM entity_occurrences
            GROUP BY doc_id
            ORDER BY timestamp DESC
        ''')
        
        docs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return docs

    def delete_document(self, doc_id: str):
        """Delete a document and its occurrences from the graph"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Delete occurrences
        cursor.execute('DELETE FROM entity_occurrences WHERE doc_id = ?', (doc_id,))
        
        # Cleanup orphan entities (entities no longer appearing in any doc)
        cursor.execute('''
            DELETE FROM graph_entities 
            WHERE entity_hash NOT IN (SELECT DISTINCT entity_hash FROM entity_occurrences)
        ''')
        
        conn.commit()
        conn.close()
        return {"status": "success", "deleted_doc_id": doc_id}

    def get_graph_data(self, limit_nodes: int = 100) -> Dict[str, List]:
        """
        Generate node-link data for visualization.
        
        Returns:
            {nodes: [...], links: [...]}
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 1. Fetch top entities (nodes)
        cursor.execute('''
            SELECT e.entity_hash, e.entity_type, e.sample_text, COUNT(o.doc_id) as doc_count
            FROM graph_entities e
            JOIN entity_occurrences o ON e.entity_hash = o.entity_hash
            GROUP BY e.entity_hash
            ORDER BY doc_count DESC
            LIMIT ?
        ''', (limit_nodes,))
        
        entity_nodes = [dict(row) for row in cursor.fetchall()]
        entity_hashes = [n['entity_hash'] for n in entity_nodes]
        
        # 2. Add document nodes if they connect multiple entities
        # (This makes the graph more informative as a bipartite-like map)
        cursor.execute('''
            SELECT doc_id, file_name, COUNT(entity_hash) as entity_count
            FROM entity_occurrences
            WHERE entity_hash IN (''' + ','.join(['?' for _ in entity_hashes]) + ''')
            GROUP BY doc_id
            HAVING entity_count > 1
        ''', entity_hashes)
        
        doc_nodes = [dict(row) for row in cursor.fetchall()]
        
        # 3. Construct Final Nodes List
        nodes = []
        for e in entity_nodes:
            nodes.append({
                "id": e["entity_hash"],
                "label": f"{e['entity_type']}: {e['sample_text'][:8]}...",
                "type": "entity",
                "entity_type": e["entity_type"],
                "val": e["doc_count"] * 2 + 5 # Scale for UI
            })
            
        for d in doc_nodes:
            nodes.append({
                "id": d["doc_id"],
                "label": d["file_name"],
                "type": "document",
                "val": d["entity_count"] + 3
            })
            
        # 4. Generate Links (Entity <-> Document)
        links = []
        cursor.execute('''
            SELECT entity_hash, doc_id 
            FROM entity_occurrences
            WHERE entity_hash IN (''' + ','.join(['?' for _ in entity_hashes]) + ''')
            AND doc_id IN (''' + ','.join(['?' for _ in [d['doc_id'] for d in doc_nodes]]) + ''')
        ''', entity_hashes + [d['doc_id'] for d in doc_nodes])
        
        for row in cursor.fetchall():
            links.append({
                "source": row[0],
                "target": row[1],
                "value": 1
            })
            
        conn.close()
        return {"nodes": nodes, "links": links}

    def detect_reidentification_chains(self) -> List[Dict]:
        """
        Identifies entities that allow linking multiple sensitive files.
        Example: A Phone number that appears in a Bank Statement AND an ID card.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find entities appearing in more than 1 document
        cursor.execute('''
            SELECT e.entity_hash, e.entity_type, e.sample_text, 
                   GROUP_CONCAT(o.file_name, ' | ') as files,
                   COUNT(DISTINCT o.doc_id) as doc_count
            FROM graph_entities e
            JOIN entity_occurrences o ON e.entity_hash = o.entity_hash
            GROUP BY e.entity_hash
            HAVING doc_count > 1
            ORDER BY doc_count DESC
        ''')
        
        chains = []
        for row in cursor.fetchall():
            chains.append({
                "entity_hash": row['entity_hash'],
                "entity_type": row['entity_type'],
                "identifier": row['sample_text'],
                "connected_files": row['files'].split(' | '),
                "risk_score": row['doc_count'] * 20,
                "recommendation": f"Break link by redacting {row['entity_type']} across these files."
            })
            
        conn.close()
        return chains

    def get_risk_summary(self) -> Dict[str, Any]:
        """Get high-level statistics about the privacy graph"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM graph_entities')
        total_entities = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM (SELECT doc_id FROM entity_occurrences GROUP BY doc_id)')
        total_docs = cursor.fetchone()[0]
        
        # Critical links (entities connecting 3+ files)
        cursor.execute('SELECT COUNT(*) FROM (SELECT entity_hash FROM entity_occurrences GROUP BY entity_hash HAVING COUNT(DISTINCT doc_id) >= 3)')
        critical_links = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "total_entities_mapped": total_entities,
            "documents_analyzed": total_docs,
            "critical_links_count": critical_links,
            "graph_density": (total_entities / total_docs) if total_docs > 0 else 0
        }

# Global instance helper
_privacy_graph = None

def get_privacy_graph() -> PrivacyGraph:
    global _privacy_graph
    if _privacy_graph is None:
        _privacy_graph = PrivacyGraph()
    return _privacy_graph
