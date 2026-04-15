import sqlite3
import os

def check_db(path, name):
    print(f"\n--- Checking {name} ({path}) ---")
    if not os.path.exists(path):
        print("❌ File does not exist!")
        return
    
    try:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables: {[t[0] for t in tables]}")
        
        for table in [t[0] for t in tables]:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"  - {table}: {count} rows")
            
            if count > 0:
                cursor.execute(f"SELECT * FROM {table} LIMIT 1")
                recent = cursor.fetchone()
                print(f"    Sample: {recent}")
                
        conn.close()
    except Exception as e:
        print(f"❌ Error: {e}")

# Paths relative to backend/
db_dir = "database"
check_db(os.path.join(db_dir, "audit.db"), "Audit DB")
check_db(os.path.join(db_dir, "scan_inventory.db"), "Inventory DB")
