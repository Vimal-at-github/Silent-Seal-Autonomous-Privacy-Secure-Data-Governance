
import os
import shutil
import sys

def reset_vault():
    print("WARNING: This will delete all encrypted files and reset the vault!")
    confirm = input("Are you sure? (type 'yes' to confirm): ")
    
    if confirm.lower() != 'yes':
        print("Operation cancelled.")
        return

    # Paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    vault_dir = os.path.join(base_dir, "vault_data")
    db_path = os.path.join(base_dir, "database", "vault.db")

    # Delete vault data
    if os.path.exists(vault_dir):
        try:
            shutil.rmtree(vault_dir)
            print(f"✅ Deleted vault data at: {vault_dir}")
        except Exception as e:
            print(f"❌ Error deleting vault data: {e}")

    # Delete database
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
            print(f"✅ Deleted vault database at: {db_path}")
        except Exception as e:
            print(f"❌ Error deleting database: {e}")
            
    print("\n✨ Vault reset complete! restart the server and go to http://localhost:8000/api/vault/initialize?password=NEW_PASSWORD to set a new one.")

if __name__ == "__main__":
    reset_vault()
