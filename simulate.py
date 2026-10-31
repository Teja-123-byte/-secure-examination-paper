#!/usr/bin/env python3
"""
simulate.py - Two-party simulation (sender / recipient folders on one machine)
plus the five required test scenarios. Writes test_results.txt.

Folder layout created under ./workshop:
  sender/     keys/ (faculty private+public)  trusted_keys/ (recipient public)  outbox/
  recipient/  keys/ (coordinator private+public) trusted_keys/ (sender public)   inbox/ decrypted/
  attacker/   keys/ (attacker pair, used for the wrong-key tests)  tampered/
"""
import json
import hashlib
import shutil
import sys
from pathlib import Path
from uuid import uuid4

import secure_exchange as se

ROOT = Path("workshop") / f"run_{uuid4().hex[:8]}"
PASS = b"workshop-passphrase"           # demo only; use a strong secret in practice
LOG = []


def log(msg=""):
    print(msg)
    LOG.append(msg)


def expect_reject(title, fn):
    try:
        fn()
    except se.SecurityError as e:
        log(f"  [PASS] {title}\n         -> {e}")
        return True
    log(f"  [FAIL] {title}: package was ACCEPTED (should have been rejected)")
    return False


def flip_b64(s: str) -> str:
    """Flip one bit in the middle of a base64 field."""
    import base64
    raw = bytearray(base64.b64decode(s))
    raw[len(raw) // 2] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def write_tampered(src, dst, mutate):
    pkg = json.loads(Path(src).read_text())
    mutate(pkg)
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text(json.dumps(pkg, indent=2))
    return dst


def resign(pkg, sender_private_key):
    from cryptography.hazmat.primitives import hashes
    pkg["signature"] = se._b64e(
        sender_private_key.sign(se._signed_bytes(pkg), se._PSS, hashes.SHA256())
    )


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    results = []

    log("=" * 72)
    log("SETUP: generating RSA-%d key pairs (sender, recipient, attacker)" % se.KEY_SIZE)
    log("=" * 72)
    log(f"Simulation folders: {ROOT}")
    se.generate_and_save_identity("faculty", ROOT / "sender/keys", PASS)
    se.generate_and_save_identity("coordinator", ROOT / "recipient/keys", PASS)
    se.generate_and_save_identity("attacker", ROOT / "attacker/keys", PASS)

    (ROOT / "sender/trusted_keys").mkdir(parents=True)
    (ROOT / "recipient/trusted_keys").mkdir(parents=True)
    shutil.copy(ROOT / "recipient/keys/coordinator_public.pem", ROOT / "sender/trusted_keys/")
    shutil.copy(ROOT / "sender/keys/faculty_public.pem", ROOT / "recipient/trusted_keys/")
    log("Public keys exchanged via trusted channel (copied into trusted_keys/).")

    sender_priv = se.load_private_key(ROOT / "sender/keys/faculty_private.pem", PASS)
    recip_priv = se.load_private_key(ROOT / "recipient/keys/coordinator_private.pem", PASS)
    attacker_priv = se.load_private_key(ROOT / "attacker/keys/attacker_private.pem", PASS)
    recip_pub_at_sender = se.load_public_key(ROOT / "sender/trusted_keys/coordinator_public.pem")
    sender_pub_at_recip = se.load_public_key(ROOT / "recipient/trusted_keys/faculty_public.pem")
    log(f"Sender fingerprint    : {se.fingerprint(sender_priv.public_key())[:32]}...")
    log(f"Recipient fingerprint : {se.fingerprint(recip_priv.public_key())[:32]}...")
    log(f"Attacker fingerprint  : {se.fingerprint(attacker_priv.public_key())[:32]}...")

    paper = ROOT / "sender/exam_paper.txt"
    shutil.copy("sample_input/exam_paper.txt", paper)
    original = paper.read_bytes()
    pkg_path = ROOT / "sender/outbox/exam_paper.pkg.json"
    se.encrypt_and_sign(paper, pkg_path, sender_priv, recip_pub_at_sender)
    inbox_pkg = ROOT / "recipient/inbox/exam_paper.pkg.json"
    inbox_pkg.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(pkg_path, inbox_pkg)

    log("\n" + "=" * 72)
    log("TEST 1: Authorised recipient recovers the original file")
    log("=" * 72)
    name, data = se.verify_and_decrypt(inbox_pkg, recip_priv, sender_pub_at_recip,
                                       ROOT / "recipient/decrypted")
    ok = (
        hashlib.sha256(data).digest() == hashlib.sha256(original).digest()
        and (ROOT / "recipient/decrypted" / name).read_bytes() == original
    )
    log(f"  [{'PASS' if ok else 'FAIL'}] Decrypted file identical to original "
        f"({len(data)} bytes, SHA-256 match = {ok})")
    results.append(ok)

    log("\n" + "=" * 72)
    log("TEST 2: Attacker modifies ciphertext / metadata / signature")
    log("=" * 72)
    T = ROOT / "attacker/tampered"
    cases = {
        "Modified ciphertext": lambda p: p.__setitem__("ciphertext", flip_b64(p["ciphertext"])),
        "Modified GCM tag": lambda p: p.__setitem__("tag", flip_b64(p["tag"])),
        "Modified nonce": lambda p: p.__setitem__("nonce", flip_b64(p["nonce"])),
        "Modified encrypted session key": lambda p: p.__setitem__(
            "encrypted_session_key", flip_b64(p["encrypted_session_key"])),
        "Modified metadata (filename changed)": lambda p: p["metadata"].__setitem__(
            "filename", "answer_key.txt"),
        "Modified metadata (recipient_id changed)": lambda p: p["metadata"].__setitem__(
            "recipient_id", "student"),
        "Modified signature": lambda p: p.__setitem__("signature", flip_b64(p["signature"])),
    }
    for title, mut in cases.items():
        tp = write_tampered(inbox_pkg, T / (title.replace(" ", "_").replace("(", "").replace(")", "") + ".json"), mut)
        results.append(expect_reject(
            title, lambda tp=tp: se.verify_and_decrypt(tp, recip_priv, sender_pub_at_recip,
                                                       ROOT / "recipient/decrypted_tampered")))
    missing_metadata = json.loads(inbox_pkg.read_text())
    del missing_metadata["metadata"]["filename"]
    resign(missing_metadata, sender_priv)
    missing_metadata_path = T / "missing_metadata.json"
    missing_metadata_path.write_text(json.dumps(missing_metadata))
    results.append(expect_reject(
        "Signed package missing required metadata",
        lambda: se.verify_and_decrypt(missing_metadata_path, recip_priv,
                                      sender_pub_at_recip,
                                      ROOT / "recipient/decrypted_tampered")))

    duplicate_field_path = T / "duplicate_field.json"
    package_text = inbox_pkg.read_text()
    duplicate_field_path.write_text(
        package_text.replace('  "tag": ', '  "tag": "duplicate",\n  "tag": ', 1)
    )
    results.append(expect_reject(
        "Package containing a duplicate JSON field",
        lambda: se.verify_and_decrypt(duplicate_field_path, recip_priv,
                                      sender_pub_at_recip,
                                      ROOT / "recipient/decrypted_tampered")))

    forged = T / "forged_by_attacker.json"
    fake = ROOT / "attacker/fake_exam.txt"
    fake.write_text("FORGED EXAM - all questions are trivial\n")
    se.encrypt_and_sign(fake, forged, attacker_priv, se.load_public_key(
        ROOT / "recipient/keys/coordinator_public.pem"), sender_id="faculty")
    results.append(expect_reject(
        "Package replaced by attacker's own signed forgery",
        lambda: se.verify_and_decrypt(forged, recip_priv, sender_pub_at_recip,
                                      ROOT / "recipient/decrypted_tampered")))
    leaked = (ROOT / "recipient/decrypted_tampered").exists()
    log(f"  [{'FAIL' if leaked else 'PASS'}] No plaintext was written for any rejected package")
    results.append(not leaked)

    log("\n" + "=" * 72)
    log("TEST 3: Decryption attempted with an incorrect private key")
    log("=" * 72)
    results.append(expect_reject(
        "Attacker's private key used to decrypt valid package",
        lambda: se.verify_and_decrypt(inbox_pkg, attacker_priv, sender_pub_at_recip,
                                      ROOT / "attacker/stolen")))
    try:
        se.load_private_key(ROOT / "recipient/keys/coordinator_private.pem", b"wrong-pass")
        log("  [FAIL] Private key loaded with wrong passphrase")
        results.append(False)
    except se.SecurityError as e:
        log(f"  [PASS] Wrong passphrase cannot unlock stored private key\n         -> {e}")
        results.append(True)

    # Defence-in-depth: packages with a VALID sender signature but inner defects,
    # so the OAEP and GCM layers are exercised independently of the signature layer.
    import base64
    from cryptography.hazmat.primitives import hashes as _h
    good = json.loads(inbox_pkg.read_text())
    bad_key = dict(good)
    bad_key["encrypted_session_key"] = base64.b64encode(
        attacker_priv.public_key().encrypt(b"x" * 32, se._OAEP)).decode()
    resign(bad_key, sender_priv)
    pk = T / "validsig_wrong_wrapped_key.json"; pk.write_text(json.dumps(bad_key))
    results.append(expect_reject(
        "Valid signature, but session key wrapped for a different RSA key (OAEP layer)",
        lambda: se.verify_and_decrypt(pk, recip_priv, sender_pub_at_recip)))
    bad_ct = dict(good)
    bad_ct["ciphertext"] = flip_b64(good["ciphertext"])
    resign(bad_ct, sender_priv)
    pk = T / "validsig_bad_ciphertext.json"; pk.write_text(json.dumps(bad_ct))
    results.append(expect_reject(
        "Valid signature, but ciphertext altered (AES-GCM tag layer)",
        lambda: se.verify_and_decrypt(pk, recip_priv, sender_pub_at_recip)))

    log("\n" + "=" * 72)
    log("TEST 4: Signature verification with an incorrect sender public key")
    log("=" * 72)
    results.append(expect_reject(
        "Verification using attacker's public key as 'trusted sender key'",
        lambda: se.verify_and_decrypt(inbox_pkg, recip_priv, attacker_priv.public_key(),
                                      ROOT / "recipient/decrypted_wrongkey")))

    log("\n" + "=" * 72)
    log("TEST 5: Same file encrypted twice -> different packages")
    log("=" * 72)
    p1 = ROOT / "sender/outbox/run1.pkg.json"
    p2 = ROOT / "sender/outbox/run2.pkg.json"
    a = se.encrypt_and_sign(paper, p1, sender_priv, recip_pub_at_sender)
    b = se.encrypt_and_sign(paper, p2, sender_priv, recip_pub_at_sender)
    for fld in ("nonce", "encrypted_session_key", "ciphertext", "tag", "signature"):
        diff = a[fld] != b[fld]
        log(f"  [{'PASS' if diff else 'FAIL'}] {fld:22s} differs between runs")
        results.append(diff)
    both = all(se.verify_and_decrypt(p, recip_priv, sender_pub_at_recip)[1] == original
               for p in (p1, p2))
    log(f"  [{'PASS' if both else 'FAIL'}] Both packages still decrypt to the original file")
    results.append(both)

    log("\n" + "=" * 72)
    log(f"SUMMARY: {sum(results)}/{len(results)} checks passed")
    log("=" * 72)

    Path("sample_output").mkdir(exist_ok=True)
    shutil.copy(pkg_path, "sample_output/exam_paper.pkg.json")
    Path("test_results.txt").write_text("\n".join(LOG) + "\n")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
