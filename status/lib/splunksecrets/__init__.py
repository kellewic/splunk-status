import base64, os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_SPLUNK_SECRET_PATH = "/opt/splunk/etc/auth/splunk.secret"


def get_splunk_secret(splunk_secret_path=DEFAULT_SPLUNK_SECRET_PATH):
    secret = None

    with open(splunk_secret_path, "rb") as splunk_secret_file:
        secret = splunk_secret_file.read().strip()

    if len(secret) < 254:
        raise ValueError("secret too short, need 254 bytes, got %d" % len(secret))

    return secret

def is_encrypted(text):
    return text.startswith("$7$")

def b64decode(encoded):
    """Wrapper around `base64.b64decode` to add padding if necessary"""
    padding_len = 4 - (len(encoded) % 4)
    if padding_len < 4:
        encoded += "=" * padding_len
    return base64.b64decode(encoded)


def decrypt(ciphertext, splunk_secret_path=DEFAULT_SPLUNK_SECRET_PATH):
    plaintext = None

    secret = get_splunk_secret(splunk_secret_path=splunk_secret_path)

    if is_encrypted(ciphertext):
        ciphertext = b64decode(ciphertext[3:])

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"disk-encryption",
            iterations=1,
            backend=default_backend()
        )
        key = kdf.derive(secret[:254])

        iv = ciphertext[:16]
        tag = ciphertext[-16:]
        ciphertext = ciphertext[16:-16]

        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, mode=modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext).decode()

    return plaintext


def encrypt_new(plaintext, splunk_secret_path=DEFAULT_SPLUNK_SECRET_PATH):
    """Use the new AES 256 GCM encryption in Splunk 7.2"""

    secret = get_splunk_secret(splunk_secret_path=splunk_secret_path)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"disk-encryption",
        iterations=1,
        backend=default_backend()
    )
    key = kdf.derive(secret[:254])

    iv = os.urandom(16)

    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return "$7$%s" % base64.b64encode(b"%s%s%s" % (iv, ciphertext, encryptor.tag)).decode()

