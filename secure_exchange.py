"""
secure_exchange.py - Core library for secure examination-paper exchange.

Primitives (all from the `cryptography` library):
  * RSA-4096 key pairs (sender and recipient are separate)
  * AES-256-GCM for bulk file encryption (fresh key + fresh 96-bit nonce per file)
  * RSA-OAEP (SHA-256, MGF1-SHA-256) to wrap the AES session key
  * RSA-PSS (SHA-256, max salt) to sign the whole encrypted package

Package layout (JSON, binary fields base64-encoded):
  {
    "metadata":            {version, filename, sender_id, recipient_id,
                            sender_fp, recipient_fp, timestamp, algorithms...},
    "encrypted_session_key": RSA-OAEP(recipient_pub, AES key),
    "nonce":               12 random bytes,
    "ciphertext":          AES-GCM ciphertext,
    "tag":                 16-byte GCM authentication tag,
    "signature":           RSA-PSS(sender_priv, canonical(all fields above))
  }

The metadata is ALSO bound into AES-GCM as Associated Data (AAD), so it is
authenticated twice: by the signature and by the GCM tag.
"""

import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 4096
AES_KEY_BYTES = 32         # AES-256
NONCE_BYTES = 12           # 96-bit nonce recommended for GCM
TAG_BYTES = 16             # 128-bit GCM tag
PACKAGE_VERSION = 1


class SecurityError(Exception):
    """Raised when any verification / decryption step fails."""


def generate_rsa_keypair(key_size: int = KEY_SIZE):
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def save_private_key(key, path, passphrase: bytes):
    """Save private key as PKCS#8 PEM, encrypted with a passphrase, mode 0600."""
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)


def save_public_key(key, path):
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def load_private_key(path, passphrase: bytes):
    try:
        return serialization.load_pem_private_key(Path(path).read_bytes(), password=passphrase)
    except (ValueError, TypeError) as e:
        raise SecurityError(f"Cannot load private key {path}: {e}")


def load_public_key(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def fingerprint(public_key) -> str:
    """SHA-256 fingerprint of the DER SubjectPublicKeyInfo (hex)."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def generate_and_save_identity(name: str, key_dir, passphrase: bytes):
    """Create <name>_private.pem (encrypted) and <name>_public.pem in key_dir."""
    key_dir = Path(key_dir)
    priv = generate_rsa_keypair()
    save_private_key(priv, key_dir / f"{name}_private.pem", passphrase)
    save_public_key(priv.public_key(), key_dir / f"{name}_public.pem")
    return priv


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _canonical(obj) -> bytes:
    """Deterministic serialization used for signing and for GCM AAD."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _signed_bytes(pkg: dict) -> bytes:
    """Everything except the signature itself is covered by the signature."""
    return _canonical({k: v for k, v in pkg.items() if k != "signature"})


_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def encrypt_and_sign(input_file, output_file, sender_private_key, recipient_public_key,
                     sender_id="faculty", recipient_id="coordinator"):
    plaintext = Path(input_file).read_bytes()

    session_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)

    metadata = {
        "version": PACKAGE_VERSION,
        "filename": Path(input_file).name,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "sender_fp": fingerprint(sender_private_key.public_key()),
        "recipient_fp": fingerprint(recipient_public_key),
        "timestamp": int(time.time()),
        "plaintext_size": len(plaintext),
        "enc_alg": "AES-256-GCM",
        "key_wrap_alg": "RSA-OAEP-SHA256",
        "sig_alg": "RSA-PSS-SHA256",
    }

    ct_and_tag = AESGCM(session_key).encrypt(nonce, plaintext, _canonical(metadata))
    ciphertext, tag = ct_and_tag[:-TAG_BYTES], ct_and_tag[-TAG_BYTES:]

    enc_session_key = recipient_public_key.encrypt(session_key, _OAEP)

    pkg = {
        "metadata": metadata,
        "encrypted_session_key": _b64e(enc_session_key),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
        "tag": _b64e(tag),
    }

    pkg["signature"] = _b64e(sender_private_key.sign(_signed_bytes(pkg), _PSS, hashes.SHA256()))

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(output_file).write_text(json.dumps(pkg, indent=2))
    return pkg


def verify_and_decrypt(package_file, recipient_private_key, trusted_sender_public_key,
                       output_dir=None):
    """
    Returns (filename, plaintext_bytes). Plaintext is only returned (and only
    written to disk) after ALL checks succeed; otherwise SecurityError is raised.
    """
    try:
        pkg = json.loads(
            Path(package_file).read_text(), object_pairs_hook=_reject_duplicate_keys
        )
        if not isinstance(pkg, dict):
            raise ValueError("package must be a JSON object")
        required = {"metadata", "encrypted_session_key", "nonce", "ciphertext", "tag", "signature"}
        if set(pkg.keys()) != required:
            raise ValueError("unexpected or missing fields")
        metadata = pkg["metadata"]
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a JSON object")
        required_metadata = {
            "version", "filename", "sender_id", "recipient_id", "sender_fp",
            "recipient_fp", "timestamp", "plaintext_size", "enc_alg",
            "key_wrap_alg", "sig_alg",
        }
        if not required_metadata.issubset(metadata):
            raise ValueError("missing required metadata")
        if not isinstance(metadata["filename"], str) or not metadata["filename"]:
            raise ValueError("invalid filename")
        filename = os.path.basename(metadata["filename"])
        if filename in ("", ".", ".."):
            raise ValueError("invalid filename")
        if not isinstance(metadata["sender_id"], str) or not metadata["sender_id"]:
            raise ValueError("invalid sender_id")
        if not isinstance(metadata["recipient_id"], str) or not metadata["recipient_id"]:
            raise ValueError("invalid recipient_id")
        if (not isinstance(metadata["timestamp"], int)
                or isinstance(metadata["timestamp"], bool)):
            raise ValueError("invalid timestamp")
        if (not isinstance(metadata["plaintext_size"], int)
                or isinstance(metadata["plaintext_size"], bool)
                or metadata["plaintext_size"] < 0):
            raise ValueError("invalid plaintext_size")
        signature = _b64d(pkg["signature"])
        enc_key = _b64d(pkg["encrypted_session_key"])
        nonce = _b64d(pkg["nonce"])
        ciphertext = _b64d(pkg["ciphertext"])
        tag = _b64d(pkg["tag"])
        if (not isinstance(metadata["version"], int)
                or isinstance(metadata["version"], bool)
                or metadata["version"] != PACKAGE_VERSION):
            raise ValueError("unsupported package version")
        if (metadata.get("enc_alg") != "AES-256-GCM"
                or metadata.get("key_wrap_alg") != "RSA-OAEP-SHA256"
                or metadata.get("sig_alg") != "RSA-PSS-SHA256"):
            raise ValueError("unsupported cryptographic algorithm")
        if len(nonce) != NONCE_BYTES or len(tag) != TAG_BYTES:
            raise ValueError("bad nonce/tag length")
    except Exception as e:
        raise SecurityError(f"REJECTED: malformed package ({e})")

    try:
        trusted_sender_public_key.verify(signature, _signed_bytes(pkg), _PSS, hashes.SHA256())
    except InvalidSignature:
        raise SecurityError("REJECTED: signature verification failed "
                            "(package modified, or not signed by the trusted sender)")
    except Exception as e:
        raise SecurityError(f"REJECTED: signature check error ({e})")

    if metadata["sender_fp"] != fingerprint(trusted_sender_public_key):
        raise SecurityError("REJECTED: sender fingerprint does not match trusted key")

    if metadata.get("recipient_fp") != fingerprint(recipient_private_key.public_key()):
        raise SecurityError("REJECTED: package is not addressed to this recipient's key")

    try:
        session_key = recipient_private_key.decrypt(enc_key, _OAEP)
    except Exception:
        raise SecurityError("REJECTED: cannot recover session key "
                            "(wrong recipient private key or corrupted key blob)")

    try:
        plaintext = AESGCM(session_key).decrypt(nonce, ciphertext + tag, _canonical(metadata))
    except InvalidTag:
        raise SecurityError("REJECTED: AES-GCM authentication tag mismatch "
                            "(ciphertext/metadata altered)")

    if len(plaintext) != metadata["plaintext_size"]:
        raise SecurityError("REJECTED: plaintext size does not match authenticated metadata")

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / filename).write_bytes(plaintext)
    return filename, plaintext
