from ElGamal import ElGamal
from ElGamal import ElGamalKey
from Crypto.Cipher import DES
from Crypto import Random

import sys


def main():
    print('Hello Gerard')

    key = b'\xf2\x1c\xccw\x13\xb9>\x8e'

    des = DES.new(key, DES.MODE_ECB)

    #Open the private key file and read its contents
    private_key_file = open("privatekey.txt", "rb")
    private_key_encrypted = private_key_file.read()

    #Decrypt the private key using the DES algorithm.
    private_key_bytes = des.decrypt(private_key_encrypted)
    #Remove all padding bytes from the decrypted private key.
    private_key = private_key_bytes.decode('utf-8').strip('\x00')

    #Close the private key file.
    private_key_file.close()

    #Open the public key file and read its contents
    public_key_file = open("publickey.txt", "r")
    public_key_string = public_key_file.read()
    #Close the public key file.
    public_key_file.close()

    #Seperate the string read from the private key using commas as delimeters.
    public_key_data = public_key_string.split(",")

    #Create a new elGamal key object using the private and public keys.
    elGamalKey = ElGamalKey(int(public_key_data[0]), int(public_key_data[1]), int(public_key_data[2]), int(private_key))

    #Open the encrypted letter file and read its contents. 
    encrypted_letter_file = open("encrypted_letter.txt", "r")
    encrypted_letter_string = encrypted_letter_file.read()
    #Close the encrypted letter file.
    encrypted_letter_file.close()

    #Sepearte the cipher text into its two fields using commas as delimeters. 
    cipher_string = encrypted_letter_string.split(",")

    #Create the cipher text as a tuple of two integers. 
    cipher_text = (int(cipher_string[0]), int(cipher_string[1]))
    #Decrypt the cipher text using the elGamal key object. 
    plaintext = elGamalKey.decrypt(cipher_text)

    #Print the plaintext to the screen. 
    print(plaintext)



if __name__ == "__main__":
    main()