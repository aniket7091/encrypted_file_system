"""
Hashing utilities for file integrity verification
"""

import hashlib


def compute_sha256_file(file_path):
    """
    Compute SHA-256 hash of a file
    
    Args:
        file_path (str): Path to file
        
    Returns:
        str: Hexadecimal hash string
    """
    sha256_hash = hashlib.sha256()
    
    # Read file in chunks to handle large files efficiently
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()


def compute_sha256_bytes(data):
    """
    Compute SHA-256 hash of byte data
    
    Args:
        data (bytes): Data to hash
        
    Returns:
        str: Hexadecimal hash string
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()


def verify_hash(computed_hash, stored_hash):
    """
    Verify if computed hash matches stored hash
    
    Args:
        computed_hash (str): Newly computed hash
        stored_hash (str): Previously stored hash
        
    Returns:
        bool: True if hashes match, False otherwise
    """
    return computed_hash.lower() == stored_hash.lower()
