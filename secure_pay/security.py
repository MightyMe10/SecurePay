"""Security utilities: password policy, hashing, and TOTP helpers."""
from __future__ import annotations

import base64
import hashlib
import re
from typing import Optional

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app


def _derive_key(source: str) -> bytes:
    digest = hashlib.sha256(source.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _get_or_create_totp_key() -> bytes:
    key = current_app.config.get("TOTP_ENCRYPTION_KEY")
    if not key:
        key = _derive_key(current_app.config["SECRET_KEY"])
        current_app.config["TOTP_ENCRYPTION_KEY"] = key.decode()
    if isinstance(key, str):
        key = key.encode()
    return key


def get_fernet() -> Fernet:
    # Encrypt TOTP secrets at rest so database leaks do not expose MFA factors.
    # Key is derived from SECRET_KEY when an explicit key is not supplied.
    return Fernet(_get_or_create_totp_key())


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> str:
    return get_fernet().encrypt(secret.encode()).decode()


def decrypt_totp_secret(token: str) -> Optional[str]:
    try:
        return get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def verify_totp(token: str, secret: str) -> bool:
    if not token or not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)


ph = PasswordHasher()

PASSWORD_POLICY = {
    "min_length": 12,
    "uppercase": re.compile(r"[A-Z]"),
    "lowercase": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r"[^A-Za-z0-9]"),
}


class PasswordPolicyError(ValueError):
    """Raised when a password does not satisfy the policy."""


def validate_password_strength(password: str) -> None:
    if len(password) < PASSWORD_POLICY["min_length"]:
        raise PasswordPolicyError("Password must be at least 12 characters long.")
    if not PASSWORD_POLICY["uppercase"].search(password):
        raise PasswordPolicyError("Include at least one uppercase letter.")
    if not PASSWORD_POLICY["lowercase"].search(password):
        raise PasswordPolicyError("Include at least one lowercase letter.")
    if not PASSWORD_POLICY["digit"].search(password):
        raise PasswordPolicyError("Include at least one digit.")
    if not PASSWORD_POLICY["special"].search(password):
        raise PasswordPolicyError("Include at least one special character.")


def hash_password(password: str, *, enforce_policy: bool = True) -> str:
    if enforce_policy:
        validate_password_strength(password)
    # Argon2id provides resistance against GPU cracking and side-channel attacks.
    return ph.hash(password)


def verify_password(hash_value: str, password: str) -> bool:
    try:
        return ph.verify(hash_value, password)
    except VerifyMismatchError:
        return False


def needs_rehash(hash_value: str) -> bool:
    return ph.check_needs_rehash(hash_value)
