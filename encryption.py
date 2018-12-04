from ElGamal import ElGamal
from Crypto.Cipher import DES
from Crypto import Random

import sys

def main():

    #Create a new ElGamal Object
    elGamalObject = ElGamal(256)

    #Generate ElGamal Key Object
    print('Generating ElGamal Key Object...\n')
    elGamalKey = elGamalObject.generate()
    print('ElGamal Key is generated.\n')

    key = b'\xf2\x1c\xccw\x13\xb9>\x8e'

    #Create new des Object
    des = DES.new(key, DES.MODE_ECB)
    #Retrieve the private key from the previously created ElGamal key.
    elgamal_private_key = elGamalKey.get_private_key()

    #Convert the private key to its byte representation.
    elgamal_private_key_encoded = elgamal_private_key.encode('utf-8')
    #Add padding bytes to the private key so that it can be encrypted using Electronic Codebook (ECB) Cipher Mode.
    while (len(elgamal_private_key_encoded) % 8) != 0:
        elgamal_private_key_encoded += bytes([0])

    #Encrypt the private key using the DES algorithm
    cipher_text = des.encrypt(elgamal_private_key_encoded)
    #Open a file to store the encrypted private key.
    privatekeyFile = open("privatekey.txt", "wb")
    #Write the encrypted private key to a text file.
    privatekeyFile.write(cipher_text)
    #Close the private key file.
    privatekeyFile.close()

    #Write the public generated from the created elgamal key object to a public key file.
    publickeyFile = open("publickey.txt", "w")
    public_key = elGamalKey.get_public_key_tuple()
    for key in public_key:
        publickeyFile.write(str(key))
        publickeyFile.write(",")
    publickeyFile.close()

    #Open a file called letter text and read the contents.
    letterFile = open("letter.txt", "rb")

    letterText = letterFile.read()

    letter_text_string = letterText.decode('utf-8')

    print('Encrypting letter...\n')

    #Encrypt the text read from the file using ElGamal method.
    letter_cipher_text = elGamalKey.encrypt(letter_text_string, 6)

    #Write the cipher text to a file called encypted_letter.txt
    encrypted_letter_file = open("encrypted_letter.txt", "w")
    encrypted_letter_file.write(str(letter_cipher_text[0]))
    encrypted_letter_file.write(",")
    encrypted_letter_file.write(str(letter_cipher_text[1]))

    print('Message encrypted successfully\n')
    print('Encrypted message file created.')

if __name__ == "__main__":
    main()