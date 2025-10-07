"""
Sample code of the second exercise of the SAT lecture
:author: Michael Kaiser
"""
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes


def RSAEncrypt(pubkey, byteArray) -> bytes:
    """
    RSA Encrypt implenmentationn
    :param pubkey: the pubkey used for encryption.
    :type pubkey: bytes
    :param byteArray: the value to be encrypted
    :type byteArray: bytes
    :return: the encrypted value
    :rtype: bytes
    """
    csp = RSA.importKey(pubkey)
    rsa_csp = PKCS1_v1_5.new(csp)
    return rsa_csp.encrypt(byteArray)


def RSADecrypt(privkey, byteArray):
    """
    RSA Decrypt implenmentationn
    :param privkey: the private key used for encryption.
    :type privkey: bytes
    :param byteArray: the encrypted value
    :type byteArray: bytes
    :return: the decrypted value
    :rtype: bytes
    """
    csp = RSA.importKey(privkey)
    rsa_csp = PKCS1_v1_5.new(csp)
    return rsa_csp.decrypt(byteArray, None)


def asymmetric_encrypt(pubkey: bytes, content: bytes) -> tuple[bytes, bytes, bytes]:
    """
    asymmetric Encrypt implenmentationn
    :param pubkey: the public key used for encryption.
    :type pubkey: bytes
    :param content: the content to be encrypted
    :type content: bytes
    :return: the encrypted value
    :rtype: tuple[bytes, bytes, bytes]
    """
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    header = b"header"
    cipher.update(header)

    encrypted_aead = cipher.encrypt(content)
    encrypted_key = RSAEncrypt(pubkey, key)

    return encrypted_aead, encrypted_key, cipher.nonce


def asymmetric_decrypt(key: bytes, content: bytes, encrypted_key: bytes, nonce: bytes) -> bytes:
    """
    asymmetric Decrypt implenmentationn
    :param key: the private key used for encryption.
    :type key: bytes
    :param content: the encrypted value
    :type content: bytes
    :param encrypted_key: the encrypted value for aead
    :type encrypted_key: bytes
    :param nonce: the short-lived nonce for the cipher
    :type nonce: bytes
    :return: the decrypted value
    :rtype: bytes
    """
    plain_key = RSADecrypt(key, encrypted_key)
    cipher = ChaCha20_Poly1305.new(key=plain_key, nonce=nonce)
    header = b"header"
    cipher.update(header)
    plain_text = cipher.decrypt(content)
    return plain_text


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate keypair and return it
    :return: The public and private key
    :rtype: tuple[bytes, bytes]
    """
    keypair = RSA.generate(3072)
    public_key = keypair.publickey().exportKey()
    private_key = keypair.exportKey()

    return public_key, private_key


def encrypt(public_key: bytes):
    """
    Encrypt with AES
    :param public_key: the public key used for encryption.
    :return: None
    """
    cipher_text, key_enc, nonce_val = asymmetric_encrypt(public_key, b'test')
    file_content = cipher_text + key_enc + nonce_val
    f = open("cipher.txt", "wb")
    f.write(file_content)
    f.close()
    print("Encrypted the content: test")


def decrypt(private_key: bytes):
    """
    Decrypt cipher text
    :param private_key: private key
    :return: None
    """
    f = open("cipher.txt", "rb")
    raw_secret = f.read()

    cipher_text = raw_secret[:len(raw_secret)-396]
    key_enc = raw_secret[len(raw_secret)-396:len(raw_secret)-12]
    nonce_val = raw_secret[len(raw_secret)-12:len(raw_secret)]

    plain = asymmetric_decrypt(private_key, cipher_text, key_enc, nonce_val)

    print(f"Decrypted the content: {plain.decode()}")


def main():
    """
    Main function
    :return: None
    """
    public_key, private_key = generate_keypair()
    encrypt(public_key)
    decrypt(private_key)


if __name__ == '__main__':
    main()
