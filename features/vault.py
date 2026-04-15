"""
SilentSeal - Encrypted Vault
Secure storage for sensitive files with master password protection
"""

import os
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hashlib


class EncryptedVault:
    """
    Encrypted vault for secure file storage.
    
    Features:
    - Master password protected vault
    - AES-256 encrypted file storage
    - RSA key pair for asymmetric sharing
    - File metadata tracking
    - Import/export of public keys
    """
    
    def __init__(self, name: str = "default", vault_base: str = None):
        """
        Initialize the encrypted vault.
        
        Args:
            name: Name of the vault
            vault_base: Base directory for all vaults
        """
        if vault_base is None:
            vault_base = os.path.join(
                os.path.dirname(__file__), "..", "..", "vaults"
            )
        
        self.name = name
        self.vault_path = os.path.join(vault_base, name)
        self.files_path = os.path.join(self.vault_path, "files")
        self.keys_path = os.path.join(self.vault_path, "keys")
        self.db_path = os.path.join(self.vault_path, "vault.db")
        self.config_path = os.path.join(self.vault_path, "config.json")
        
        self._is_unlocked = False
        self._master_key = None
        self._aes = None
        self._rsa = None
    
    def initialize(self, master_password: str) -> Dict[str, Any]:
        """
        Initialize a new vault with master password.
        
        Args:
            master_password: Master password for the vault
            
        Returns:
            Initialization status
        """
        # Check if already initialized
        if os.path.exists(self.config_path):
            return {"status": "error", "message": "Vault already initialized"}
        
        # Create directories
        os.makedirs(self.vault_path, exist_ok=True)
        os.makedirs(self.files_path, exist_ok=True)
        os.makedirs(self.keys_path, exist_ok=True)
        
        # Load encryption modules
        from features.encryption import AESEncryption, RSAEncryption
        self._aes = AESEncryption()
        self._rsa = RSAEncryption()
        
        # Create password verification hash
        password_salt = os.urandom(16)
        password_hash = self._hash_password(master_password, password_salt)
        
        # Generate RSA key pair for sharing
        private_key_pem, public_key_pem = self._rsa.generate_key_pair()
        
        # Encrypt private key with master password
        encrypted_private_key = self._aes.encrypt(private_key_pem, master_password)
        
        # Save encrypted private key
        with open(os.path.join(self.keys_path, "private.key.enc"), 'wb') as f:
            f.write(encrypted_private_key)
        
        # Save public key (not encrypted - meant to be shared)
        with open(os.path.join(self.keys_path, "public.key"), 'wb') as f:
            f.write(public_key_pem)
        
        # Save config
        config = {
            "version": "1.0",
            "created": datetime.now(timezone.utc).isoformat(),
            "password_salt": password_salt.hex(),
            "password_hash": password_hash.hex(),
            "key_algorithm": "RSA-4096",
            "encryption_algorithm": "AES-256-GCM"
        }
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Initialize database
        self._init_database()
        
        return {
            "status": "success",
            "message": "Vault initialized successfully",
            "vault_path": self.vault_path,
            "public_key_path": os.path.join(self.keys_path, "public.key")
        }
    
    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash password with salt using PBKDF2"""
        from hashlib import pbkdf2_hmac
        return pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    def _init_database(self):
        """Initialize vault database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                vault_name TEXT UNIQUE NOT NULL,
                original_path TEXT,
                file_hash TEXT,
                original_size INTEGER,
                encrypted_size INTEGER,
                added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS shared_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                public_key_hash TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                added_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vault_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                file_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def unlock(self, master_password: str) -> Dict[str, Any]:
        """
        Unlock the vault with master password.
        
        Args:
            master_password: Master password
            
        Returns:
            Unlock status
        """
        if not os.path.exists(self.config_path):
            return {"status": "error", "message": "Vault not initialized"}
        
        # Load config
        with open(self.config_path, 'r') as f:
            config = json.load(f)
        
        # Verify password
        password_salt = bytes.fromhex(config["password_salt"])
        password_hash = self._hash_password(master_password, password_salt)
        
        if password_hash.hex() != config["password_hash"]:
            return {"status": "error", "message": "Invalid master password"}
        
        # Load encryption modules
        from features.encryption import AESEncryption, RSAEncryption
        self._aes = AESEncryption()
        self._rsa = RSAEncryption()
        
        self._master_key = master_password
        self._is_unlocked = True
        
        return {
            "status": "success",
            "message": "Vault unlocked",
            "files_count": self._get_files_count()
        }
    
    def lock(self) -> Dict[str, Any]:
        """Lock the vault"""
        self._is_unlocked = False
        self._master_key = None
        return {"status": "success", "message": "Vault locked"}
    
    def is_unlocked(self) -> bool:
        """Check if vault is unlocked"""
        return self._is_unlocked
    
    def _get_files_count(self) -> int:
        """Get count of files in vault"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM vault_files')
        count = cursor.fetchone()[0]
        conn.close()
        return count
    
    def add_file(self, file_path: str, delete_original: bool = False) -> Dict[str, Any]:
        """
        Add a file to the vault (encrypts and stores).
        
        Args:
            file_path: Path to file to add
            delete_original: Whether to delete original after adding
            
        Returns:
            Add operation result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        if not os.path.exists(file_path):
            return {"status": "error", "message": "File not found"}
        
        # Get file info
        original_name = os.path.basename(file_path)
        file_hash = self._compute_file_hash(file_path)
        original_size = os.path.getsize(file_path)
        
        # Generate vault filename
        vault_name = f"{file_hash}_{original_name}.enc"
        vault_file_path = os.path.join(self.files_path, vault_name)
        
        # Encrypt file
        result = self._aes.encrypt_file(file_path, vault_file_path, self._master_key)
        
        if result["status"] != "success":
            return result
        
        encrypted_size = os.path.getsize(vault_file_path)
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO vault_files 
            (original_name, vault_name, original_path, file_hash, original_size, encrypted_size)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (original_name, vault_name, file_path, file_hash, original_size, encrypted_size))
        
        cursor.execute('''
            INSERT INTO vault_log (action, file_name, details)
            VALUES (?, ?, ?)
        ''', ('ADD', original_name, f"Added from {file_path}"))
        
        conn.commit()
        conn.close()
        
        # Delete original if requested
        if delete_original:
            os.remove(file_path)
        
        return {
            "status": "success",
            "original_name": original_name,
            "vault_name": vault_name,
            "original_size": original_size,
            "encrypted_size": encrypted_size
        }
    
    def extract_file(self, vault_name: str, output_path: str) -> Dict[str, Any]:
        """
        Extract a file from the vault (decrypts to destination).
        
        Args:
            vault_name: Name of file in vault
            output_path: Path to extract to
            
        Returns:
            Extract operation result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        vault_file_path = os.path.join(self.files_path, vault_name)
        
        if not os.path.exists(vault_file_path):
            return {"status": "error", "message": "File not found in vault"}
        
        # Decrypt file
        result = self._aes.decrypt_file(vault_file_path, output_path, self._master_key)
        
        if result["status"] == "success":
            # Log extraction
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vault_log (action, file_name, details)
                VALUES (?, ?, ?)
            ''', ('EXTRACT', vault_name, f"Extracted to {output_path}"))
            conn.commit()
            conn.close()
        
        return result
    
    def remove_file(self, vault_name: str) -> Dict[str, Any]:
        """
        Remove a file from the vault.
        
        Args:
            vault_name: Name of file in vault
            
        Returns:
            Remove operation result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        vault_file_path = os.path.join(self.files_path, vault_name)
        
        if not os.path.exists(vault_file_path):
            return {"status": "error", "message": "File not found in vault"}
        
        # Remove file
        os.remove(vault_file_path)
        
        # Update database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM vault_files WHERE vault_name = ?', (vault_name,))
        cursor.execute('''
            INSERT INTO vault_log (action, file_name, details)
            VALUES (?, ?, ?)
        ''', ('REMOVE', vault_name, "Removed from vault"))
        
        conn.commit()
        conn.close()
        
        return {"status": "success", "message": f"Removed {vault_name}"}
    
    def list_files(self) -> List[Dict[str, Any]]:
        """List all files in the vault"""
        if not self._is_unlocked:
            return []
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT original_name, vault_name, original_size, encrypted_size, added_time
            FROM vault_files
            ORDER BY added_time DESC
        ''')
        
        files = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return files
    
    def get_public_key(self) -> bytes:
        """Get the vault's public key for sharing"""
        public_key_path = os.path.join(self.keys_path, "public.key")
        
        if os.path.exists(public_key_path):
            with open(public_key_path, 'rb') as f:
                return f.read()
        return None
    
    def encrypt_for_sharing(self, file_path: str, recipient_public_key: bytes,
                            output_path: str) -> Dict[str, Any]:
        """
        Encrypt a file for sharing with a recipient.
        
        Args:
            file_path: Path to file to encrypt
            recipient_public_key: Recipient's public key (PEM)
            output_path: Path for encrypted output
            
        Returns:
            Encryption result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        from features.encryption import RSAEncryption
        rsa = RSAEncryption()
        
        result = rsa.encrypt_file_for_recipient(file_path, output_path, recipient_public_key)
        
        if result["status"] == "success":
            # Log sharing
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO vault_log (action, file_name, details)
                VALUES (?, ?, ?)
            ''', ('SHARE', os.path.basename(file_path), "Encrypted for recipient"))
            conn.commit()
            conn.close()
        
        return result
    
    def decrypt_shared_file(self, encrypted_file_path: str, 
                             output_path: str) -> Dict[str, Any]:
        """
        Decrypt a file that was shared with us.
        
        Args:
            encrypted_file_path: Path to encrypted file
            output_path: Path for decrypted output
            
        Returns:
            Decryption result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        # Load our private key
        private_key_path = os.path.join(self.keys_path, "private.key.enc")
        
        with open(private_key_path, 'rb') as f:
            encrypted_private_key = f.read()
        
        # Decrypt private key
        private_key_pem = self._aes.decrypt(encrypted_private_key, self._master_key)
        
        # Decrypt file
        from features.encryption import RSAEncryption
        rsa = RSAEncryption()
        
        result = rsa.decrypt_file_with_private_key(
            encrypted_file_path, output_path, private_key_pem
        )
        
        return result
    
    def import_public_key(self, name: str, public_key_pem: bytes) -> Dict[str, Any]:
        """
        Import a recipient's public key for sharing.
        
        Args:
            name: Name/label for the key
            public_key_pem: Public key in PEM format
            
        Returns:
            Import result
        """
        if not self._is_unlocked:
            return {"status": "error", "message": "Vault is locked"}
        
        # Hash the key for uniqueness check
        key_hash = hashlib.sha256(public_key_pem).hexdigest()[:16]
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO shared_keys (name, public_key_hash, public_key)
                VALUES (?, ?, ?)
            ''', (name, key_hash, public_key_pem.decode()))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return {"status": "error", "message": "Key already exists"}
        
        conn.close()
        
        return {"status": "success", "name": name, "key_hash": key_hash}
    
    def list_imported_keys(self) -> List[Dict[str, Any]]:
        """List all imported public keys"""
        if not self._is_unlocked:
            return []
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT name, public_key_hash, added_time
            FROM shared_keys
            ORDER BY added_time DESC
        ''')
        
        keys = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return keys
    
    def get_imported_key(self, key_hash: str) -> Optional[bytes]:
        """Get an imported public key by hash"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT public_key FROM shared_keys WHERE public_key_hash = ?',
            (key_hash,)
        )
        
        row = cursor.fetchone()
        conn.close()
        
        return row[0].encode() if row else None
    
    def _compute_file_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]
    
    def change_master_password(self, old_password: str, 
                                new_password: str) -> Dict[str, Any]:
        """
        Change the vault master password.
        
        Args:
            old_password: Current password
            new_password: New password
            
        Returns:
            Change result
        """
        # Verify old password first
        unlock_result = self.unlock(old_password)
        if unlock_result["status"] != "success":
            return {"status": "error", "message": "Invalid current password"}
        
        # Re-encrypt private key with new password
        private_key_path = os.path.join(self.keys_path, "private.key.enc")
        
        with open(private_key_path, 'rb') as f:
            encrypted_private_key = f.read()
        
        # Decrypt with old password
        private_key_pem = self._aes.decrypt(encrypted_private_key, old_password)
        
        # Encrypt with new password
        new_encrypted_private_key = self._aes.encrypt(private_key_pem, new_password)
        
        with open(private_key_path, 'wb') as f:
            f.write(new_encrypted_private_key)
        
        # Update password hash
        with open(self.config_path, 'r') as f:
            config = json.load(f)
        
        new_salt = os.urandom(16)
        new_hash = self._hash_password(new_password, new_salt)
        
        config["password_salt"] = new_salt.hex()
        config["password_hash"] = new_hash.hex()
        
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Update master key
        self._master_key = new_password
        
        return {"status": "success", "message": "Password changed successfully"}
    
    def get_vault_stats(self) -> Dict[str, Any]:
        """Get vault statistics"""
        if not os.path.exists(self.db_path):
            return {"status": "not_initialized"}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM vault_files')
        files_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT SUM(original_size), SUM(encrypted_size) FROM vault_files')
        row = cursor.fetchone()
        original_size = row[0] or 0
        encrypted_size = row[1] or 0
        
        cursor.execute('SELECT COUNT(*) FROM shared_keys')
        keys_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "status": "unlocked" if self._is_unlocked else "locked",
            "files_count": files_count,
            "original_size_bytes": original_size,
            "encrypted_size_bytes": encrypted_size,
            "imported_keys_count": keys_count,
            "vault_path": self.vault_path
        }


# Multi-vault management
_vaults: Dict[str, EncryptedVault] = {}
_active_vault: str = "default"

def get_vault(name: str = None) -> EncryptedVault:
    """Get or create a vault instance by name"""
    global _active_vault
    if name is None:
        name = _active_vault
    
    if name not in _vaults:
        _vaults[name] = EncryptedVault(name=name)
    return _vaults[name]

def set_active_vault(name: str):
    """Set the system-wide active vault"""
    global _active_vault
    _active_vault = name
    if name not in _vaults:
        _vaults[name] = EncryptedVault(name=name)

def list_existing_vaults() -> List[str]:
    """List all initialized vaults on disk"""
    vault_base = os.path.join(os.path.dirname(__file__), "..", "..", "vaults")
    if not os.path.exists(vault_base):
        return []
    
    vaults = []
    for item in os.listdir(vault_base):
        item_path = os.path.join(vault_base, item)
        if os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, "config.json")):
            vaults.append(item)
    return vaults
