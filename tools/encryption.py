"""
AGY Bug Bounty MCP - Field-Level Encryption for Sensitive Data
Uses Fernet (AES-128-CBC with PKCS7 padding) for encrypting sensitive findings.
"""
import os
import logging
from cryptography.fernet import Fernet
from typing import Optional

logger = logging.getLogger("agy")

# Get or generate encryption key
def _get_encryption_key() -> bytes:
    """Get encryption key from environment or generate one."""
    key = os.getenv("ENCRYPTION_KEY")
    if key:
        return key.encode() if isinstance(key, str) else key
    # Generate a key for development - WARNING: this will break decryption on restart
    logger.warning("[ENCRYPTION] No ENCRYPTION_KEY set - using ephemeral key (NOT FOR PRODUCTION)")
    return Fernet.generate_key()

_fernet = Fernet(_get_encryption_key())

# Fields that should be encrypted for sensitive findings
SENSITIVE_FIELDS = {"payload", "evidence", "steps_to_reproduce"}


def encrypt_value(plaintext: str) -> str:
    """Encrypt a string value using Fernet.
    
    Args:
        plaintext: The string to encrypt
        
    Returns:
        Encrypted string (base64-encoded) or original if encryption fails
    """
    if not plaintext:
        return plaintext
    try:
        return _fernet.encrypt(plaintext.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return plaintext


def decrypt_value(encrypted: str) -> str:
    """Decrypt a Fernet-encrypted string.
    
    Args:
        encrypted: The encrypted string (base64-encoded)
        
    Returns:
        Decrypted string or original if decryption fails
    """
    if not encrypted:
        return encrypted
    try:
        return _fernet.decrypt(encrypted.encode()).decode()
    except Exception as e:
        logger.debug(f"Decryption failed (may not be encrypted): {e}")
        return encrypted


def encrypt_sensitive_dict(data: dict, fields: set = SENSITIVE_FIELDS) -> dict:
    """Encrypt specified fields in a dictionary.
    
    Args:
        data: Dictionary with sensitive fields
        fields: Set of field names to encrypt
        
    Returns:
        Dictionary with specified fields encrypted
    """
    result = data.copy()
    for field in fields:
        if field in result and result[field]:
            result[field] = encrypt_value(result[field])
    return result


def decrypt_sensitive_dict(data: dict, fields: set = SENSITIVE_FIELDS) -> dict:
    """Decrypt specified fields in a dictionary.
    
    Args:
        data: Dictionary with encrypted fields
        fields: Set of field names to decrypt
        
    Returns:
        Dictionary with specified fields decrypted
    """
    result = data.copy()
    for field in fields:
        if field in result and result[field]:
            result[field] = decrypt_value(result[field])
    return result