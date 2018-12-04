from Crypto import PublicKey
from Crypto.Util import number
from Crypto import Random

import math

class ElGamalKey:

    # ElGamal Key Object has four properties. 
    # p: The Modulus
    # g: The Generator
    # d: Private Key
    # e: Public Key
    def __init__(self, p, g, e, d ,randomFunction=None):
        self.p = p
        self.g = g
        self.e = e
        self.d = d

        #If no random function is given, create a new one. 
        if randomFunction is None:
            randomFunction = Random.new().read
        self.randomFunction = randomFunction

    #Return the private key of the current ElGamal Key Object.
    def get_private_key(self):
        return str(self.d)

    #Returns the public key of the current ElGamal Key Object
    def get_public_key(self):
        return str(self.e)

    def get_public_key_tuple(self):
        return (self.p, self.g, self.e)

    #Given a plaintext message to be encrypted and a random number, encrypts the plaintext message using the ElGamal method.  
    def encrypt(self, M, K):
        #Convert the given message into bytes and then convert to an integer. 
        i = int.from_bytes(M.encode('utf-8'), byteorder='big')
        #Calculate C1 using the following: g^k(mod p)
        a = pow(self.g, K, self.p)
        #Calculate C2 using the following: Me^k (mod p)
        b = ( i * pow(self.e, K, self.p)) % self.p
        #Return the two calculated values as a tuple. 
        return (a, b)

    def encrypt_bytes(self, M, K):
        i = int.from_bytes(M, byteorder='big')
        a = pow(self.g, K, self.p)
        b = ( i * pow(self.e, K, self.p)) % self.p
        return (a, b)

    #bytes_needed accepts an integer and returns the length of the byte representation of the given integer. 
    def bytes_needed(self, data):
        if data == 0:
            return 1
        return int(math.log(data, 256)) + 1

    #Accepts a message block C = (C1, C2) given a private key d
    def decrypt(self, M):
        #Decrypt the encrypted message.
        c_one = pow(M[0], self.d, self.p)
        plaintextInteger = self.mod_divide(M[1], c_one, self.p)
        #Get the length of the byte representation of the Integer.
        bytes_length = self.bytes_needed(plaintextInteger)
        #Convert the Integer to bytes
        plaintext_bytes = int.to_bytes(plaintextInteger, length=bytes_length, byteorder='big')
        #Convert the byte representation to a string which is the decrypted plaintext 
        plaintext = plaintext_bytes.decode('utf-8')
        #return the plaintext message.
        return plaintext

    #The function mod_divide calculates a/b under modulo m.
    def mod_divide(self, a, b, m):
        a = a % m
        my_inverse = number.inverse(b, m)
        #The inverse does not exist.
        if my_inverse == -1:
            return -1
        return (my_inverse * a) % m

    def decrypt_method2(self, M):
        #Check if the class has a private key. If there is none throw an error. 
        if (not hasattr(self, 'd')):
            raise TypeError('Private Key Not Available')

        #Get a random number, k such that: 1 < k < p.
        k = number.getRandomRange(2, self.p - 1, self.randomFunction)
        #compute a_blind = (C1 * g^k (mod p)) mod p
        a_blind = (M[0] * pow(self.g, k, self.p)) % self.p 
 
        ax = pow(a_blind, self.d, self.p)

        plaintext_blind = (M[1] * number.inverse(ax, self.p)) % self.p

        plaintextInteger = (plaintext_blind * pow(self.e, k, self.p)) % self.p
        #Get the length of byte representation of the decrypted Integer 
        bytes_length = self.bytes_needed(plaintextInteger)
        #Convert the decrypted integer to bytes. 
        plaintext_bytes = int.to_bytes(plaintextInteger, length=bytes_length, byteorder='big')
        #Convert the byte representation to a string.
        plaintext = plaintext_bytes.decode('utf-8')
        #return the decrypted plaintext.
        return plaintext

class ElGamal:
 
    def __init__(self, key_size):
        self.key_size = key_size

    def generate(self, randFunc=None):
        #Generate a large prime number, p, of the given key size. 
        p = number.getPrime(self.key_size, randFunc) 
        #Select a number, g, that is a primitive element of modulo p.
        g = self.find_primitive_root(p)
        #select a private key, d, such that 1 < d < p - 1. 
        d = number.getRandomRange(2, p, randFunc)
        #create a public key e as: e = g^d (mod p)
        e = pow(g, d, p)
        #Create and returns an elgamal key object. 
        result = ElGamalKey(p, g, e, d)

        return result

    def find_prime_factors(self, n):
        #Create an empty list
        s = list()

        #Add the number of two's that divide n to the list. 
        while n%2 == 0:
            s.append(2)
            n = n/2

        for i in range(3, int(math.sqrt(n)) + 1, 2):
            while n%i == 0:
                s.append(i)
                n = n/i
        if n > 2:
            s.append(n)
        
        return s

    def find_primitive_root(self, n):
        s = list()

        #Determine if n is prime.
        if not number.isPrime(n):
            return -1

        #We know that n is prime here. The value if the Euler Totient function of n is n - 1 because n is prime. 
        phi = n - 1
        #get all prime factors of n - 1. 
        s = self.find_prime_factors(phi)
        #Check all values from 2 to phi. 
        for i in range(2, phi):
            flag = False
            #Iterate through all prime factors ph phi and check to see if a value with a power of 1 is found. 
            for factor in s:
                if(pow(i, int(phi // factor), n) == 1):
                    flag = True
                    break
            #If no value with power one is found, return i. 
            if flag == False:
                return i

        #If no primitive root is found.
        return -1
