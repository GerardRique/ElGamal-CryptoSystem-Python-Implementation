from ElGamal import ElGamal
from ElGamal import ElGamalKey
from Crypto.Cipher import DES
from Crypto import Random

import sys


def main():
    print('Hello Gerard')

    key = b'\xf2\x1c\xccw\x13\xb9>\x8e'

    des = DES.new(key, DES.MODE_ECB)

    private_key_file = open("privatekey.txt", "rb")
    private_key_encrypted = private_key_file.read()

    private_key_bytes = des.decrypt(private_key_encrypted)

    private_key = private_key_bytes.decode('utf-8')

    private_key_file.close()

    public_key_file = open("publickey.txt", "r")

    public_key_string = public_key_file.read()

    public_key_file.close()

    public_key_data = public_key_string.split(",")

    elGamalKey = ElGamalKey(public_key_data[0], public_key_data[1], public_key_data[2], private_key)

    print(elGamalKey.d)

    print(elGamalKey.p)

    print(elGamalKey.g)

    print(elGamalKey.e)



if __name__ == "__main__":
    main()