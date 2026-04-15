import hashlib, json, os

def check_vault(path, password):
    if not os.path.exists(path):
        return False
    with open(path, 'r') as f:
        config = json.load(f)
    salt = bytes.fromhex(config['password_salt'])
    stored_hash = config['password_hash']
    computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
    return stored_hash == computed_hash

password = 'admin123'
print(f"Checking vaults for password: {password}")
print(f"Default Vault: {check_vault('d:/vimal2/silentseal/vaults/default/config.json', password)}")
print(f"Vimal Vault:   {check_vault('d:/vimal2/silentseal/vaults/Vimal/config.json', password)}")
