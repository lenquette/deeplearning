import sys
import os
import json
import base64
import binascii
from os.path import dirname, abspath
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# add pinckle's location folder
ProjectFileDirParent = dirname(dirname(abspath(__file__)))
DashboardTransitDir = os.path.join(ProjectFileDirParent, '.transit/')
sys.path.append(DashboardTransitDir)


def cryptedkey():
    password_data = b"B5gjhlr84P"
    salt = os.urandom(16)
    salt_before = binascii.hexlify(os.urandom(8))
    salt_after = binascii.hexlify(os.urandom(4))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000)
    private_key = base64.urlsafe_b64encode(kdf.derive(password_data))

    #re-solt to make it unreadable
    private_key = salt_before + private_key + salt_after

    # store the key salted
    with open(os.path.join(DashboardTransitDir,'private_key.pem'), 'wb') as f:
        f.write(private_key)

    return 0


def crypted_json(to_crypt_data):

    #generate the random key
    cryptedkey()

    #read data key
    with open(os.path.join(DashboardTransitDir,'private_key.pem'), 'rb') as key_file:
        private_key = key_file.read()

    private_key = private_key[16:-8]
    print(len(private_key))
    private_key = Fernet(private_key)

    token = private_key.encrypt(bytes(json.dumps(to_crypt_data), 'utf-8'))
    return token


def uncrypt_json(crypted_data):

    #read data key
    with open(os.path.join(DashboardTransitDir,'private_key.pem'), 'rb') as key_file:
        private_key = key_file.read()

    private_key = private_key[16:-8]

    private_key = Fernet(private_key)
    var = private_key.decrypt(crypted_data).decode('utf8')
    print(private_key)
    return json.loads(var)
