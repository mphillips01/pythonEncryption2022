from base64 import b64encode, b64decode
import rsa

# create function to create rsa key pair

def createRsaKeyPair():
    # create key pair
    (publicKey, privateKey) = rsa.newkeys(2048)
    # create public and private key files
    publicKeyFile = open("rsaPublicKey.txt", "wb")
    publicKeyPemFile = open("keys/publicKey.pem", "wb")
    privateKeyFile = open("rsaPrivateKey.txt", "wb")
    privateKeyPemFile = open("keys/privateKey.pem", "wb")
    # write public key to public key file
    publicKeyFile.write(publicKey.save_pkcs1())
    publicKeyPemFile.write(publicKey.save_pkcs1(format='PEM'))
    # write private key to private key file
    privateKeyFile.write(privateKey.save_pkcs1())
    privateKeyPemFile.write(privateKey.save_pkcs1(format='PEM'))
    # close files
    publicKeyFile.close()
    publicKeyPemFile.close()
    privateKeyFile.close()
    privateKeyPemFile.close()
    return (publicKey, privateKey)

#read rsa public key
def readRsaPublicKey():
    with open("keys/publicKey.pem", "rb") as publicKeyFile:
        publicKey = rsa.PublicKey.load_pkcs1(publicKeyFile.read())
    publicKeyFile.close()
    return publicKey

# read rsa private key
def readRsaPrivateKey():
    with open("keys/privateKey.pem", "rb") as privateKeyFile:
        privateKey = rsa.PrivateKey.load_pkcs1(privateKeyFile.read())
    privateKeyFile.close()
    return privateKey

# encrypt fernet key using public key
def rsaEncrypt(key):
    # read fernet key
    fernetKeyFile = open("fernetKey.txt", "r")
    fernetKeyString = fernetKeyFile.read()
    fernetKeyFile.close()
    #copy fernet key and save it to rsa_sym_key_plain.txt
    fernetKeyFileCopy = open("rsa_sym_key_plain.txt", "w")
    #fernetKeyString = b64encode(key).decode('utf-8')
    fernetKeyFileCopy.write(fernetKeyString)
    fernetKeyFileCopy.close()
    # encrypt fernet key using public key
    fernetKeyStringBytes = fernetKeyString.encode()
    encryptedFernetKey = rsa.encrypt(fernetKeyStringBytes, key)
    # write encrypted fernet key to file
    encryptedFernetKeyFile = open("rsa_sym_key_cipher.txt", "wb")
    #encryptedFernetKeyString = b64encode(encryptedFernetKey).decode('utf-8')
    encryptedFernetKeyFile.write(encryptedFernetKey)
    encryptedFernetKeyFile.close()
    return encryptedFernetKey

def rsaDecrypt(key):
    # read encrypted fernet key
    encryptedFernetKeyFile = open("rsa_sym_key_cipher.txt", "rb")
    encryptedFernetKey = encryptedFernetKeyFile.read()
    encryptedFernetKeyFile.close()
    # decrypt fernet key using private key
    decryptedFernetKey = rsa.decrypt(encryptedFernetKey, key)
    # write decrypted fernet key to file
    decryptedFernetKeyFile = open("rsa_sym_key_decrypted.txt", "wb")
    decryptedFernetKeyFile.write(decryptedFernetKey)
    decryptedFernetKeyFile.close()
    return decryptedFernetKey


#createRsaKeyPair()
#rsaEncrypt(readRsaPublicKey())
rsaDecrypt(readRsaPrivateKey())