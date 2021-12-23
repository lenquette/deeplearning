import sys
import os
import json
import base64
import binascii
from os.path import dirname, abspath
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# add pinckle's location folder to store the data extract from nmap
ProjectFileDirParent = dirname(dirname(abspath(__file__)))
DashboardTransitDir = os.path.join(ProjectFileDirParent, '.transit/')
sys.path.append(DashboardTransitDir)


def cryptedkey():
    '''
    Generate a key to crypt
    @return: 0 if any error occurred
    '''
    #seed of the key
    password_data = b"B5gjhlr84P"
    salt = os.urandom(16)
    #salt for after generation of the key in order to protect it from malicious people
    salt_before = binascii.hexlify(os.urandom(8))
    salt_after = binascii.hexlify(os.urandom(4))
    #generation of the key
    kdf = PBKDF2HMAC(
        backend=default_backend(), #might work without
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
    '''

    @param to_crypt_data: json data to crypt
    @return: json data crypted as a string
    '''

    #generate the random key
    cryptedkey()

    #read data key
    with open(os.path.join(DashboardTransitDir,'private_key.pem'), 'rb') as key_file:
        private_key = key_file.read()

    #extract salt
    private_key = private_key[16:-8]
    private_key = Fernet(private_key)

    #converts json in string then encrypts it
    token = private_key.encrypt(bytes(json.dumps(to_crypt_data), 'utf-8'))
    return token


def uncrypt_json(crypted_data):
    '''
    @param crypted_data: srting data of the crypted json
    @return: json decrypted
    '''

    #read data key
    with open(os.path.join(DashboardTransitDir, 'private_key.pem'), 'rb') as key_file:
        private_key = key_file.read()

    #extract salt
    private_key = private_key[16:-8]

    #verification of the key and decryption
    private_key = Fernet(private_key)
    var = private_key.decrypt(crypted_data).decode('utf8')
    return json.loads(var)
