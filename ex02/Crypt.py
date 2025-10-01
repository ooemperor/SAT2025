"""
Sample code of the second exercise of the SAT lecture
:author: Michael Kaiser
"""
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def main():
    aes_key = get_random_bytes(16)

    cipher = AES.new(aes_key, AES.MODE_CTR)

    print(cipher)


if __name__ == '__main__':
    main()