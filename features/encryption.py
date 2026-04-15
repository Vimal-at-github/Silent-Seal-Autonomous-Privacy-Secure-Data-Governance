"""
SilentSeal - Encryption Module
AES-256 symmetric and RSA asymmetric encryption
"""

import os
import base64
import secrets
from typing import Tuple, Optional, Dict, Any
from pathlib import Path


class AESEncryption:
    """
    AES-256 symmetric encryption for file protection.
    
    Uses:
    - AES-256-GCM for authenticated encryption
    - PBKDF2 for key derivation from password
    - Secure random salt and nonce generation
    """
    
    # Constants
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for GCM
    SALT_SIZE = 16  # 128 bits
    ITERATIONS = 480000  # PBKDF2 iterations (OWASP recommendation)
    
    def __init__(self):
        self._fernet = None
        self._backend = None
        self._load_crypto()
    
    def _load_crypto(self):
        """Load cryptography library"""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            self._backend = default_backend()
            self._crypto_available = True
        except ImportError:
            print("Warning: cryptography library not installed")
            self._crypto_available = False
    
    def derive_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Optional salt (generated if not provided)
            
        Returns:
            Tuple of (derived_key, salt)
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        
        if salt is None:
            salt = secrets.token_bytes(self.SALT_SIZE)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=self._backend
        )
        
        key = kdf.derive(password.encode())
        return key, salt
    
    def encrypt(self, data: bytes, password: str) -> bytes:
        """
        Encrypt data with password.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted data (salt + nonce + ciphertext + tag)
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Derive key
        key, salt = self.derive_key(password)
        
        # Generate nonce
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Encrypt with AES-GCM
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        # Return salt + nonce + ciphertext (includes auth tag)
        return salt + nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypt data with password.
        
        Args:
            encrypted_data: Encrypted data
            password: Decryption password
            
        Returns:
            Decrypted data
            
        Raises:
            Exception if decryption fails (wrong password or corrupted data)
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Extract components
        salt = encrypted_data[:self.SALT_SIZE]
        nonce = encrypted_data[self.SALT_SIZE:self.SALT_SIZE + self.NONCE_SIZE]
        ciphertext = encrypted_data[self.SALT_SIZE + self.NONCE_SIZE:]
        
        # Derive key with same salt
        key, _ = self.derive_key(password, salt)
        
        # Decrypt
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def encrypt_file(self, input_path: str, output_path: str, password: str) -> Dict[str, Any]:
        """
        Encrypt a file.
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output
            password: Encryption password
            
        Returns:
            Encryption result metadata
        """
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted_data = self.encrypt(data, password)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return {
            "status": "success",
            "input_file": input_path,
            "output_file": output_path,
            "original_size": len(data),
            "encrypted_size": len(encrypted_data)
        }
    
    def decrypt_file(self, input_path: str, output_path: str, password: str) -> Dict[str, Any]:
        """
        Decrypt a file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            password: Decryption password
            
        Returns:
            Decryption result metadata
        """
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            data = self.decrypt(encrypted_data, password)
        except Exception as e:
            return {
                "status": "error",
                "message": "Decryption failed - wrong password or corrupted file"
            }
        
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "status": "success",
            "input_file": input_path,
            "output_file": output_path,
            "decrypted_size": len(data)
        }


class RSAEncryption:
    """
    RSA asymmetric encryption for secure file sharing.
    
    Uses:
    - RSA-4096 for key generation
    - OAEP padding with SHA-256
    - Hybrid encryption (RSA + AES) for large files
    """
    
    KEY_SIZE = 4096  # bits
    
    def __init__(self):
        self._crypto_available = False
        self._load_crypto()
    
    def _load_crypto(self):
        """Load cryptography library"""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            self._backend = default_backend()
            self._crypto_available = True
        except ImportError:
            print("Warning: cryptography library not installed")
    
    def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new RSA key pair.
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_SIZE,
            backend=self._backend
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Extract and serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt_for_recipient(self, data: bytes, recipient_public_key_pem: bytes) -> bytes:
        """
        Encrypt data for a recipient using their public key.
        Uses hybrid encryption: RSA encrypts an AES key, AES encrypts the data.
        
        Args:
            data: Data to encrypt
            recipient_public_key_pem: Recipient's public key in PEM format
            
        Returns:
            Encrypted data (encrypted_aes_key_length + encrypted_aes_key + aes_encrypted_data)
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Load public key
        public_key = serialization.load_pem_public_key(
            recipient_public_key_pem,
            backend=self._backend
        )
        
        # Generate random AES key
        aes_key = secrets.token_bytes(32)  # 256 bits
        nonce = secrets.token_bytes(12)
        
        # Encrypt AES key with RSA
        encrypted_aes_key = public_key.encrypt(
            aes_key + nonce,  # Include nonce with key
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encrypt data with AES
        aesgcm = AESGCM(aes_key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        
        # Pack: key_length (2 bytes) + encrypted_key + encrypted_data
        key_length = len(encrypted_aes_key).to_bytes(2, 'big')
        return key_length + encrypted_aes_key + encrypted_data
    
    def decrypt_with_private_key(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """
        Decrypt data using private key.
        
        Args:
            encrypted_data: Encrypted data from encrypt_for_recipient
            private_key_pem: Private key in PEM format
            
        Returns:
            Decrypted data
        """
        if not self._crypto_available:
            raise RuntimeError("Cryptography library not available")
        
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self._backend
        )
        
        # Unpack
        key_length = int.from_bytes(encrypted_data[:2], 'big')
        encrypted_aes_key = encrypted_data[2:2 + key_length]
        encrypted_content = encrypted_data[2 + key_length:]
        
        # Decrypt AES key with RSA
        aes_key_and_nonce = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        aes_key = aes_key_and_nonce[:32]
        nonce = aes_key_and_nonce[32:]
        
        # Decrypt data with AES
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_content, None)
        
        return plaintext
    
    def encrypt_file_for_recipient(self, input_path: str, output_path: str,
                                    recipient_public_key_pem: bytes) -> Dict[str, Any]:
        """Encrypt a file for a recipient"""
        with open(input_path, 'rb') as f:
            data = f.read()
        
        encrypted = self.encrypt_for_recipient(data, recipient_public_key_pem)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted)
        
        return {
            "status": "success",
            "input_file": input_path,
            "output_file": output_path,
            "original_size": len(data),
            "encrypted_size": len(encrypted)
        }
    
    def decrypt_file_with_private_key(self, input_path: str, output_path: str,
                                       private_key_pem: bytes) -> Dict[str, Any]:
        """Decrypt a file using private key"""
        with open(input_path, 'rb') as f:
            encrypted = f.read()
        
        try:
            data = self.decrypt_with_private_key(encrypted, private_key_pem)
        except Exception as e:
            return {
                "status": "error",
                "message": f"Decryption failed: {str(e)}"
            }
        
        with open(output_path, 'wb') as f:
            f.write(data)
        
        return {
            "status": "success",
            "input_file": input_path,
            "output_file": output_path,
            "decrypted_size": len(data)
        }


def get_aes_encryption() -> AESEncryption:
    """Get AES encryption instance"""
    return AESEncryption()


def get_rsa_encryption() -> RSAEncryption:
    """Get RSA encryption instance"""
    return RSAEncryption()
