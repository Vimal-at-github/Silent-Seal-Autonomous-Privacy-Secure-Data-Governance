import sqlite3
import os
import json

def sync():
    audit_db = "database/audit.db"
    inventory_db = "database/scan_inventory.db"
    
    if not os.path.exists(audit_db):
        print("Audit DB missing")
        return
        
    conn_audit = sqlite3.connect(audit_db)
    cursor_audit = conn_audit.cursor()
    
    conn_inv = sqlite3.connect(inventory_db)
    cursor_inv = conn_inv.cursor()
    
    # Get all uploads
    cursor_audit.execute("SELECT doc_id, filename, file_size FROM document_uploads")
    uploads = cursor_audit.fetchall()
    print(f"Syncing {len(uploads)} uploads...")
    
    for doc_id, filename, size in uploads:
        # Get risk level if exists
        cursor_audit.execute("SELECT risk_level, risk_score FROM risk_assessments WHERE doc_id = ?", (doc_id,))
        risk = cursor_audit.fetchone()
        level = risk[0] if risk else "LOW"
        score = risk[1] if risk else 0.0
        
        # Get entities count
        cursor_audit.execute("SELECT COUNT(*) FROM entity_detections WHERE doc_id = ?", (doc_id,))
        count = cursor_audit.fetchone()[0]
        
        # Insert into inventory
        cursor_inv.execute('''
            INSERT OR REPLACE INTO scanned_files 
            (file_path, file_name, file_size, file_hash, risk_level, risk_score, entities_count, entity_types)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (f"uploads/{doc_id}", filename, size, doc_id[:16], level, score, count, ""))
    
    conn_audit.close()
    conn_inv.commit()
    conn_inv.close()
    print("✅ Sync complete")

if __name__ == "__main__":
    sync()
