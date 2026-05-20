import hashlib
import random
import ssl
import base64
from Crypto.Cipher import DES, ARC4, Blowfish, AES
from Crypto.Hash import MD5, SHA1

# Weak hash: MD5 for password storage
def hash_password_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

# Weak hash: SHA1 for password storage
def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()

# Weak hash: MD5 via PyCrypto
def hash_data_md5(data):
    h = MD5.new()
    h.update(data.encode())
    return h.hexdigest()

# Insecure random for security token generation
def generate_session_token():
    return str(random.randint(100000, 999999))

# Insecure random for password reset token
def generate_reset_token():
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(32))

# DES encryption (56-bit, broken)
def encrypt_des(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

# RC4 stream cipher (broken)
def encrypt_rc4(data, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(data)

# AES in ECB mode (insecure mode, leaks patterns)
def encrypt_aes_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# SSL: certificate verification disabled
def make_insecure_request(url):
    import requests
    return requests.get(url, verify=False)

# SSL: creating unverified context
def create_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# Hardcoded IV (initialization vector)
STATIC_IV = b"\x00" * 16

def encrypt_with_static_iv(data, key):
    cipher = AES.new(key, AES.MODE_CBC, iv=STATIC_IV)
    return cipher.encrypt(data)

# Base64 used as encryption
def fake_encrypt(data):
    return base64.b64encode(data.encode()).decode()
