from base64 import b64decode, b64encode
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from rsa import decrypt

# create funciton to create fernet key
def createFernetKey():
    key = Fernet.generate_key()
    keyFile = open("fernetKey.txt", "w")
    keyString = b64encode(key).decode('utf-8')
    keyFile.write(keyString)
    keyFile.close()
    return key

# create function to read fernet key
def readFernetKey():
    keyFile = open("fernetKey.txt", "r")
    keyString = keyFile.read()
    keyFile.close()
    key = b64decode(keyString)
    return key

# create function to encrypt file using fernet key 
def fernetEncrypt(key):
    fileName = "secretFile.txt"
    # read file
    file = open(fileName, "r")
    fileString = file.read()
    file.close()
    # encrypt file
    f = Fernet(key)
    encryptedFile = f.encrypt(fileString.encode())
    # write encrypted file
    encryptedFileFile = open("secretFileCipher.txt", "wb")
    encryptedFileFile.write(encryptedFile)
    encryptedFileFile.close()
    print(encryptedFile)
    return encryptedFile

# create function to decrypt file using fernet key
def fernetDecrypt(key):
    fileName = "secretFileCipher.txt"
    # read file
    file = open(fileName, "rb")
    fileBytes = file.read()
    file.close()
    # decrypt file
    f = Fernet(key)
    decryptedFile = f.decrypt(fileBytes)
    # write decrypted file
    decryptedFileFile = open("secretFileDecrypted.txt", "w")
    decryptedFileFile.write(decryptedFile.decode())
    decryptedFileFile.close()
    return decryptedFile


#fernetEncrypt(createFernetKey())

fernetDecrypt(readFernetKey())