import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rsa import decrypt
from base64 import b64encode
#from asymmetricEncryption import *

def aesEncrypt():
    key = os.urandom(32)
    aesKeyFile = open("aesKey.txt", "w")
    keyString = b64encode(key).decode('utf-8')
    aesKeyFile.write(keyString)
    aesKeyFile.close()

    iv = os.urandom(16)
    aesIvFile = open("aesIV.txt", "w")
    ivString = b64encode(iv).decode('utf-8')
    aesIvFile.write(ivString)
    aesIvFile.close()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    secretFile = open("secretFile.txt", "r")
    secretFileString = secretFile.read()
    secretFileBytes = secretFileString.encode()
    secretFile.close()
    print(secretFileBytes)
    cipherTextBytes = encryptor.update(b"secretFileBytes") + encryptor.finalize()
    cipherText = b64encode(cipherTextBytes).decode('utf-8')

    secretFileCipherFile = open("secretFileCipher.txt", "w")
    secretFileCipherFile.write(cipherText)
    secretFileCipherFile.close()


# def aesDecrypt():
#     decryptor = cipher.decryptor()
#     plainText = decryptor.update(cipherTextBytes) + decryptor.finalize()

#     print(plainText)

aesEncrypt()
