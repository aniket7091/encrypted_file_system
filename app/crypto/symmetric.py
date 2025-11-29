"""
Symmetric encryption utilities for SecureShare
Implements AES-256, 3DES, Blowfish, and ChaCha20
"""

from Crypto.Cipher import AES, DES3, Blowfish, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt_aes_256_gcm(data):
    """
    Encrypt data using AES-256 in GCM mode (Authenticated Encryption)
    
    Args:
        data (bytes): Data to encrypt
        
    Returns:
        tuple: (encrypted_data, key, nonce)
    """
    # Generate random 256-bit (32 bytes) key
    key = get_random_bytes(32)
    
    # Create AES cipher in GCM mode
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Encrypt and get authentication tag
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    # Combine nonce, tag, and ciphertext
    encrypted_data = cipher.nonce + tag + ciphertext
    
    return encrypted_data, key, cipher.nonce


def decrypt_aes_256_gcm(encrypted_data, key, nonce):
    """
    Decrypt data encrypted with AES-256-GCM
    
    Args:
        encrypted_data (bytes): Encrypted data (nonce + tag + ciphertext)
        key (bytes): Encryption key
        nonce (bytes): Nonce used during encryption
        
    Returns:
        bytes: Decrypted data
    """
    # Extract components (nonce is first 16 bytes, tag is next 16 bytes)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Create cipher and decrypt
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext


def encrypt_3des_cbc(data):
    """
    Encrypt data using Triple DES in CBC mode
    
    Args:
        data (bytes): Data to encrypt
        
    Returns:
        tuple: (encrypted_data, key, iv)
    """
    # Generate random 192-bit (24 bytes) key for 3DES
    key = get_random_bytes(24)
    
    # Generate random IV (8 bytes for DES)
    iv = get_random_bytes(8)
    
    # Create 3DES cipher in CBC mode
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    
    # Pad data to block size (8 bytes for DES) and encrypt
    padded_data = pad(data, DES3.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return ciphertext, key, iv


def decrypt_3des_cbc(encrypted_data, key, iv):
    """
    Decrypt data encrypted with 3DES-CBC
    
    Args:
        encrypted_data (bytes): Encrypted data
        key (bytes): Encryption key
        iv (bytes): Initialization vector
        
    Returns:
        bytes: Decrypted data
    """
    # Create cipher and decrypt
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_data)
    
    # Remove padding
    plaintext = unpad(padded_plaintext, DES3.block_size)
    
    return plaintext


def encrypt_blowfish_cbc(data):
    """
    Encrypt data using Blowfish in CBC mode
    
    Args:
        data (bytes): Data to encrypt
        
    Returns:
        tuple: (encrypted_data, key, iv)
    """
    # Generate random 128-bit (16 bytes) key
    key = get_random_bytes(16)
    
    # Generate random IV (8 bytes for Blowfish)
    iv = get_random_bytes(8)
    
    # Create Blowfish cipher in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # Pad data to block size (8 bytes) and encrypt
    padded_data = pad(data, Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    return ciphertext, key, iv


def decrypt_blowfish_cbc(encrypted_data, key, iv):
    """
    Decrypt data encrypted with Blowfish-CBC
    
    Args:
        encrypted_data (bytes): Encrypted data
        key (bytes): Encryption key
        iv (bytes): Initialization vector
        
    Returns:
        bytes: Decrypted data
    """
    # Create cipher and decrypt
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(encrypted_data)
    
    # Remove padding
    plaintext = unpad(padded_plaintext, Blowfish.block_size)
    
    return plaintext


def encrypt_chacha20(data):
    """
    Encrypt data using ChaCha20 stream cipher
    
    Args:
        data (bytes): Data to encrypt
        
    Returns:
        tuple: (encrypted_data, key, nonce)
    """
    # Generate random 256-bit (32 bytes) key
    key = get_random_bytes(32)
    
    # Create ChaCha20 cipher (nonce is generated automatically)
    cipher = ChaCha20.new(key=key)
    
    # Encrypt data
    ciphertext = cipher.encrypt(data)
    
    return ciphertext, key, cipher.nonce


def decrypt_chacha20(encrypted_data, key, nonce):
    """
    Decrypt data encrypted with ChaCha20
    
    Args:
        encrypted_data (bytes): Encrypted data
        key (bytes): Encryption key
        nonce (bytes): Nonce used during encryption
        
    Returns:
        bytes: Decrypted data
    """
    # Create cipher with same key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    
    # Decrypt data (XOR operation, same as encryption)
    plaintext = cipher.decrypt(encrypted_data)
    
    return plaintext


def encrypt_file(data, algorithm):
    """
    Encrypt file data using specified algorithm
    
    Args:
        data (bytes): File data to encrypt
        algorithm (str): Algorithm name (AES, 3DES, Blowfish, ChaCha20)
        
    Returns:
        tuple: (encrypted_data, key, iv_or_nonce)
        
    Raises:
        ValueError: If algorithm is not supported
    """
    algorithm = algorithm.upper()
    
    if algorithm == 'AES':
        return encrypt_aes_256_gcm(data)
    elif algorithm == '3DES':
        return encrypt_3des_cbc(data)
    elif algorithm == 'BLOWFISH':
        return encrypt_blowfish_cbc(data)
    elif algorithm == 'CHACHA20':
        return encrypt_chacha20(data)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")


def decrypt_file(encrypted_data, key, iv_or_nonce, algorithm):
    """
    Decrypt file data using specified algorithm
    
    Args:
        encrypted_data (bytes): Encrypted file data
        key (bytes): Encryption key
        iv_or_nonce (bytes): IV or nonce used during encryption
        algorithm (str): Algorithm name (AES, 3DES, Blowfish, ChaCha20)
        
    Returns:
        bytes: Decrypted data
        
    Raises:
        ValueError: If algorithm is not supported
    """
    algorithm = algorithm.upper()
    
    if algorithm == 'AES':
        return decrypt_aes_256_gcm(encrypted_data, key, iv_or_nonce)
    elif algorithm == '3DES':
        return decrypt_3des_cbc(encrypted_data, key, iv_or_nonce)
    elif algorithm == 'BLOWFISH':
        return decrypt_blowfish_cbc(encrypted_data, key, iv_or_nonce)
    elif algorithm == 'CHACHA20':
        return decrypt_chacha20(encrypted_data, key, iv_or_nonce)
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
