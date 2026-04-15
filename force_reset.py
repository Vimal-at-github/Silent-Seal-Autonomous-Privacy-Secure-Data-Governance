
import sys
import os
import shutil

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from features.vault import get_vault, EncryptedVault

def force_reset():
    print("Starting Force Reset...")
    
    # Get vault path
    vault = get_vault()
    vault_path = vault.vault_path
    
    print(f"Vault Path: {vault_path}")
    
    # Check if exists
    if os.path.exists(vault_path):
        print("Vault exists. Deleting...")
        try:
            shutil.rmtree(vault_path)
            print("Deleted old vault.")
        except Exception as e:
            print(f"Error deleting vault: {e}")
            return
            
    # Re-initialize
    print("Initializing new vault with password '1234'...")
    # Create new instance to ensure clean state
    new_vault = EncryptedVault()
    result = new_vault.initialize("1234")
    
    print(f"Result: {result}")

if __name__ == "__main__":
    force_reset()
