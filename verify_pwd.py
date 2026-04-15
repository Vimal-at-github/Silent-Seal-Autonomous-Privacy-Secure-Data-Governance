import sqlite3, hashlib
db_path = 'd:/vimal2/silentseal/backend/database/rbac.db'
password = 'admin123'

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
user = conn.cursor().execute('SELECT salt, password_hash FROM users WHERE username="admin"').fetchone()

if user:
    salt = user['salt']
    stored_hash = user['password_hash']
    computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    print(f"Stored Hash:   {stored_hash}")
    print(f"Computed Hash: {computed_hash}")
    print(f"Match: {stored_hash == computed_hash}")
else:
    print("User 'admin' not found.")
conn.close()
