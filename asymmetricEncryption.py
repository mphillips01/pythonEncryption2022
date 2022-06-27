from base64 import b64encode
import rsa

# create function to create rsa key pair

def createRsaKeyPair():
    # create key pair
    (publicKey, privateKey) = rsa.newkeys(2048)
    # create public and private key files
    publicKeyFile = open("rsaPublicKey.txt", "wb")
    privateKeyFile = open("rsaPrivateKey.txt", "wb")
    # write public key to public key file
    publicKeyFile.write(publicKey.save_pkcs1())
    # write private key to private key file
    privateKeyFile.write(privateKey.save_pkcs1())
    # close files
    publicKeyFile.close()
    privateKeyFile.close()
    return (publicKey, privateKey)

#read rsa public key
def readRsaPublicKey():
    publicKeyFile = open("rsaPublicKey.txt", "rb")
    publicKey = publicKeyFile.read()
    publicKeyFile.close()
    return publicKey

# read rsa private key
def readRsaPrivateKey():
    privateKeyFile = open("rsaPrivateKey.txt", "rb")
    privateKey = privateKeyFile.read()
    privateKeyFile.close()
    return privateKey

# encrypt fernet key using public key
def rsaEncrypt(key):
    # read fernet key
    fernetKeyFile = open("fernetKey.txt", "r")
    fernetKeyString = fernetKeyFile.read()
    fernetKeyFile.close()
    #copy fernet key and save it to rsa_sym_key_plain.txt
    fernetKeyFile = open("rsa_sym_key_plain.txt", "w")
    fernetKeyString = b64encode(key).decode('utf-8')
    fernetKeyFile.write(fernetKeyString)
    fernetKeyFile.close()
    # encrypt fernet key using public key
    encryptedFernetKey = rsa.encrypt(fernetKeyString, key)
    # write encrypted fernet key to file
    encryptedFernetKeyFile = open("rsa_sym_key_cipher.txt", "w")
    encryptedFernetKeyString = b64encode(encryptedFernetKey).decode('utf-8')
    encryptedFernetKeyFile.write(encryptedFernetKeyString)
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
    decryptedFernetKeyFile = open("rsa_sym_key_decrypted.txt", "w")
    decryptedFernetKeyFile.write(decryptedFernetKey)
    decryptedFernetKeyFile.close()
    return decryptedFernetKey


createRsaKeyPair()
rsaEncrypt(readRsaPublicKey())