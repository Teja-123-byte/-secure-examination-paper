# Secure Examination-Paper Exchange

A Python demonstration of sending an examination paper from a faculty member
to an authorised coordinator over an untrusted channel. The sender and
recipient use separate RSA key pairs. Public keys are assumed to have been
authenticated and exchanged through a trusted channel.

## Cryptographic design

- **RSA-4096** generates separate sender and recipient key pairs.
- **AES-256-GCM** encrypts the paper with a fresh random session key and
  96-bit nonce. The metadata is authenticated as additional data.
- **RSA-OAEP with SHA-256** encrypts the session key for the recipient.
- **RSA-PSS with SHA-256** signs the complete package (metadata, encrypted
  session key, nonce, ciphertext, and authentication tag).
- On receipt, the program verifies the signature and recipient key, unwraps
  the session key, and checks the GCM tag. It writes plaintext only after all
  checks succeed.

## Project files

| File | Purpose |
|---|---|
| `secure_exchange.py` | Key management, package encryption/signing, and verification/decryption |
| `app.py` | Command-line interface for key generation, encryption, and decryption |
| `simulate.py` | Sender/recipient folder simulation and security tests |
| `sample_input/exam_paper.txt` | Sample plaintext input |
| `sample_output/exam_paper.pkg.json` | Example encrypted and signed package |
| `test_results.txt` | Latest saved simulation results |
| `sequence_diagram.png` | Sequence diagram image |

## Requirements and tests

From the project directory, install the dependencies and run the simulation:

```powershell
python -m pip install -r requirements.txt
python simulate.py
```

The simulation creates a new `workshop/run_<id>/` directory for each run. It
does not overwrite previous run directories. It also refreshes
`sample_output/exam_paper.pkg.json` and `test_results.txt`.

The simulation checks successful recovery of the original file, package
tampering and forgery, incorrect recipient and sender keys, and encrypting the
same input twice. The saved results should end with `SUMMARY: 23/23 checks
passed`.

## Two-party CLI demonstration (Windows PowerShell)

The following commands demonstrate separate sender and recipient folders on
one computer. When prompted, use a strong passphrase for each private key.
Use the same passphrase for both identities only if desired.

```powershell
python app.py keygen --name faculty --key-dir sender\keys
python app.py keygen --name coordinator --key-dir recipient\keys

New-Item -ItemType Directory -Force sender\trusted_keys, recipient\trusted_keys | Out-Null
Copy-Item recipient\keys\coordinator_public.pem sender\trusted_keys\
Copy-Item sender\keys\faculty_public.pem recipient\trusted_keys\

python app.py encrypt --input sample_input\exam_paper.txt --output sender\outbox\exam_paper.pkg.json --sender-key sender\keys\faculty_private.pem --recipient-pub sender\trusted_keys\coordinator_public.pem
New-Item -ItemType Directory -Force recipient\inbox | Out-Null
Copy-Item sender\outbox\exam_paper.pkg.json recipient\inbox\

python app.py decrypt --package recipient\inbox\exam_paper.pkg.json --output-dir recipient\decrypted --recipient-key recipient\keys\coordinator_private.pem --sender-pub recipient\trusted_keys\faculty_public.pem
```

The public-key copies in `trusted_keys` represent the trusted-channel exchange.
In an actual exchange, verify the key fingerprints over an independent trusted
channel before relying on them. Keep private keys and their passphrases
confidential; do not commit them to source control. On Windows, restrict
private-key file and folder access with account permissions.

## Sequence diagram

The image version is available at [sequence_diagram.png](sequence_diagram.png).

## Security properties and limitations

- **Confidentiality:** AES-GCM encrypts the paper; RSA-OAEP protects the
  session key so only the intended recipient's private key can recover it.
- **Integrity:** the GCM tag authenticates the ciphertext and metadata, and
  the signature covers all package fields other than the signature itself.
  Changes to these fields are rejected.
- **Sender authentication:** a valid signature verifies under the sender
  public key that was trusted through the assumed authenticated exchange.
- **Fail-closed decryption:** signature, recipient-key, key-unwrapping, and
  GCM checks must succeed before the output file is written.

Each encryption generates a new session key and nonce; encryption also uses
randomised OAEP and PSS operations. This makes repeated encryptions of the
same file produce different packages. As with any random nonce, uniqueness is
probabilistic rather than an absolute guarantee.

This is a workshop demonstration, not a production deployment. The simulation
uses the fixed passphrase `workshop-passphrase` for test keys; it must not be
used to protect real papers. A timestamp is included in each package, but
replay of a previously valid package is not prevented.
