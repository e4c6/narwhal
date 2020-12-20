import secrets
import string
import pgpy
from datetime import timedelta
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


def generate_password(n: int):
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(n))
    return password


def generate_key(key_pass: str, key_label: str, valid_for: int):
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(key_label)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA512, HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                compression=[CompressionAlgorithm.BZ2, CompressionAlgorithm.Uncompressed],
                key_expires=timedelta(days=valid_for))
    key.protect(key_pass, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key, key.pubkey


def encrypt_message(msg, priv_key, priv_pass, target_pubkey):
    with priv_key.unlock(priv_pass):
        msg = pgpy.PGPMessage.new(msg)
        msg |= priv_key.sign(msg)
        encrypted_txt = target_pubkey.encrypt(msg)
        return encrypted_txt


def decrypt_message(encrypted_blob, priv_key, priv_pass):
    msg = pgpy.PGPMessage.from_blob(encrypted_blob)
    with priv_key.unlock(priv_pass):
        decr_message = priv_key.decrypt(msg).message
        return decr_message


def verify_signer(encrypted_txt, expected_pubkey):
    if expected_pubkey.verify(encrypted_txt):
        return True
    return False


def load_key_file(path):
    key, _ = pgpy.PGPKey.from_file(path)
    return key


def load_key_blob(blob):
    key, _ = pgpy.PGPKey.from_blob(blob)
    return key


def unlock_key(key, passw):
    try:
        with key.unlock(passw):
            return True
    except:
        return False
