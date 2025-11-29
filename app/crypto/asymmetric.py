"""
RSA asymmetric encryption utilities for SecureShare
Used for protecting symmetric encryption keys
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keypair(private_key_path, public_key_path, key_size=2048):
    """
    Generate RSA key pair and save to files
    
    Args:
        private_key_path (str): Path to save private key
        public_key_path (str): Path to save public key
        key_size (int): Key size in bits (default: 2048)
        
    Returns:
        tuple: (private_key, public_key) as RSA key objects
    """
    # Generate RSA key pair
    key = RSA.generate(key_size)
    
    # Export private key
    private_key = key.export_key()
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    
    # Export public key
    public_key = key.publickey().export_key()
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
    
    print(f"RSA key pair generated successfully:")
    print(f"  Private key: {private_key_path}")
    print(f"  Public key: {public_key_path}")
    
    return key, key.publickey()


def load_rsa_keys(private_key_path, public_key_path):
    """
    Load RSA keys from files
    
    Args:
        private_key_path (str): Path to private key file
        public_key_path (str): Path to public key file
        
    Returns:
        tuple: (private_key, public_key) as RSA key objects
    """
    # Load private key
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Load public key
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    return private_key, public_key


def get_or_create_rsa_keys(private_key_path, public_key_path):
    """
    Get existing RSA keys or create new ones if they don't exist
    
    Args:
        private_key_path (str): Path to private key file
        public_key_path (str): Path to public key file
        
    Returns:
        tuple: (private_key, public_key) as RSA key objects
    """
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("Loading existing RSA keys...")
        return load_rsa_keys(private_key_path, public_key_path)
    else:
        print("Generating new RSA keys...")
        return generate_rsa_keypair(private_key_path, public_key_path)


def encrypt_key_with_rsa(symmetric_key, public_key):
    """
    Encrypt a symmetric key using RSA public key
    
    This is used in hybrid encryption: the symmetric key is encrypted
    with RSA so it can be safely stored in the database.
    
    Args:
        symmetric_key (bytes): Symmetric encryption key to protect
        public_key (RSA key object): RSA public key
        
    Returns:
        bytes: Encrypted symmetric key
    """
    # Create RSA cipher with OAEP padding (secure padding scheme)
    cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the symmetric key
    encrypted_key = cipher.encrypt(symmetric_key)
    
    return encrypted_key


def decrypt_key_with_rsa(encrypted_key, private_key):
    """
    Decrypt a symmetric key using RSA private key
    
    This is used to recover the symmetric key for file decryption.
    
    Args:
        encrypted_key (bytes): RSA-encrypted symmetric key
        private_key (RSA key object): RSA private key
        
    Returns:
        bytes: Decrypted symmetric key
    """
    # Create RSA cipher with OAEP padding
    cipher = PKCS1_OAEP.new(private_key)
    
    # Decrypt the symmetric key
    symmetric_key = cipher.decrypt(encrypted_key)
    
    return symmetric_key
