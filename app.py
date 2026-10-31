#!/usr/bin/env python3
"""
app.py - Command-line interface for the secure exam-paper exchange.

Examples
  python app.py keygen  --name faculty     --key-dir workshop/sender/keys
  python app.py keygen  --name coordinator --key-dir workshop/recipient/keys
  python app.py encrypt --input exam_paper.txt --output package.json \
        --sender-key workshop/sender/keys/faculty_private.pem \
        --recipient-pub workshop/sender/trusted_keys/coordinator_public.pem
  python app.py decrypt --package package.json --output-dir workshop/recipient/decrypted \
        --recipient-key workshop/recipient/keys/coordinator_private.pem \
        --sender-pub workshop/recipient/trusted_keys/faculty_public.pem

Private-key passphrase is read from the env var EXAM_KEY_PASSPHRASE, or prompted.
"""
import argparse
import getpass
import os
import sys

import secure_exchange as se


def get_passphrase(confirm=False) -> bytes:
    p = os.environ.get("EXAM_KEY_PASSPHRASE")
    if p is None:
        p = getpass.getpass("Private-key passphrase: ")
        if confirm and getpass.getpass("Confirm passphrase: ") != p:
            sys.exit("Passphrases do not match.")
    return p.encode()


def main():
    ap = argparse.ArgumentParser(description="Secure examination-paper exchange")
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen"); k.add_argument("--name", required=True); k.add_argument("--key-dir", required=True)

    e = sub.add_parser("encrypt")
    e.add_argument("--input", required=True); e.add_argument("--output", required=True)
    e.add_argument("--sender-key", required=True); e.add_argument("--recipient-pub", required=True)

    d = sub.add_parser("decrypt")
    d.add_argument("--package", required=True); d.add_argument("--output-dir", required=True)
    d.add_argument("--recipient-key", required=True); d.add_argument("--sender-pub", required=True)

    a = ap.parse_args()
    try:
        if a.cmd == "keygen":
            print(f"Generating RSA-{se.KEY_SIZE} key pair (may take a few seconds)...")
            se.generate_and_save_identity(a.name, a.key_dir, get_passphrase(confirm=True))
            print(f"Saved {a.key_dir}/{a.name}_private.pem (encrypted) and {a.name}_public.pem")
        elif a.cmd == "encrypt":
            priv = se.load_private_key(a.sender_key, get_passphrase())
            pub = se.load_public_key(a.recipient_pub)
            se.encrypt_and_sign(a.input, a.output, priv, pub)
            print(f"Encrypted + signed package written to {a.output}")
        elif a.cmd == "decrypt":
            priv = se.load_private_key(a.recipient_key, get_passphrase())
            spub = se.load_public_key(a.sender_pub)
            name, data = se.verify_and_decrypt(a.package, priv, spub, a.output_dir)
            print(f"SUCCESS: signature, key unwrap and GCM tag verified. "
                  f"Wrote {len(data)} bytes to {a.output_dir}/{name}")
    except se.SecurityError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
