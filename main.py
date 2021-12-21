import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def keys_generation(symmetric_key_path: str,
                    public_key_path: str,
                    private_key_path: str) -> None:
   
    print("HYBRID SYSTEM KEY GENERATION\n\n")
    
    symmetric_key = os.urandom(16) 
    print("Symmetric key:")
    print(symmetric_key)
    print("\n")

    keys = rsa.generate_private_key(public_exponent=65537, 
                                    key_size=2048)
    
    private_key = keys
    print("Asymmetric private key:")
    print(private_key)
    with open(private_key_path, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    print("\nSERIALIZED\n\n")

    public_key = keys.public_key()
    print("Asymmetric public key:")
    print(public_key)
    with open(public_key_path, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("\nSERIALIZED\n\n")

    text = bytes(symmetric_key)
    dc_text = public_key.encrypt(text, 
                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                              algorithm=hashes.SHA256(), 
                                              label=None))
    with open(symmetric_key_path, 'wb') as file:
        file.write(dc_text)
    print("Symmetric key: ENCRYPTED WITH A PUBLIC KEY\n\n\n\n")


def hybrid_encryption(text_path: str,
                      private_key_path: str,
                      symmetric_key_path: str,
                      encrypted_text_path: str,
                      ini_vector_path: str) -> None:

    print("DATA ENCRYPTION BY HYBRID SYSTEM\n\n")

    with open(symmetric_key_path, 'rb') as file: 
        public_key = file.read()
        
    with open(private_key_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(),
                                                         password=None)

    symmetric_key = private_key.decrypt(public_key,
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))
    print("Symmetric key: DECRYPTED\n\n")

    with open(text_path, 'r') as file:
        original_text = file.read()

    padder = padding2.ANSIX923(32).padder()
    text = bytes(original_text, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()

    ini_vector = os.urandom(8)

    with open(ini_vector_path, 'wb') as file:
        file.write(ini_vector)

    cipher = Cipher(algorithms.IDEA(symmetric_key),
                    modes.CBC(ini_vector))
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(padded_text)

    with open(encrypted_text_path, 'wb') as file:
        file.write(encrypted_text)
    print("Text: ENCRYPTED\n\n\n\n")


def hybrid_decryption(encrypted_text_path: str,
                      private_key_path: str,
                      symmetric_path: str,
                      decrypted_text_path: str,
                      ini_vector_path: str) -> None:

    print("DATA DECRYPTION BY HYBRID SYSTEM\n\n")

    with open(symmetric_path, 'rb') as file:
        public_key = file.read()
    with open(private_key_path, 'rb') as file:
        private_key = serialization.load_pem_private_key(file.read(),
                                                         password=None)

    symmetric_key = private_key.decrypt(public_key,
                                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))
    print("Symmetric key: DECRYPTED\n\n")

    with open(encrypted_text_path, 'rb') as file:
        encrypted_text = file.read()

    with open(ini_vector_path, 'rb') as file:
        ini_vector = file.read()

    cipher = Cipher(algorithms.IDEA(symmetric_key),
                    modes.CBC(ini_vector))

    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(32).unpadder()
    unpadded_dec_text = unpadder.update(decrypted_text)

    with open(decrypted_text_path, 'w') as file:
        file.write(str(unpadded_dec_text))
    print("Text: DECRYPTED\n\n\n\n")


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', help='Start keys generation', dest='generation')
group.add_argument('-enc', '--encryption', help='Start encryption data', dest='encryption')
group.add_argument('-dec', '--decryption', help='Start decryption data', dest='decryption')

parser.add_argument('symmetric_key_path', help='Symmetric key')
parser.add_argument('public_key_path', help='Public key')
parser.add_argument('private_key_path', help='Private key')
parser.add_argument('text_path', help='Text')
parser.add_argument('encrypted_text_path', help='Encrypted text')
parser.add_argument('decrypted_text_path', help='Decrypted text')
parser.add_argument('ini_vector_path', help='Initialization vector')

args = parser.parse_args()

if args.generation:
    keys_generation(args.symmetric_key_path,
                    args.public_key_path,
                    args.private_key_path)

if args.encryption:
    hybrid_encryption(args.text_path,
                      args.private_key_path,
                      args.symmetric_key_path,
                      args.encrypted_text_path,
                      args.ini_vector_path)

if args.decryption:
    hybrid_decryption(args.encrypted_text_path,
                      args.private_key_path,
                      args.symmetric_key_path,
                      args.decrypted_text_path,
                      args.ini_vector_path)
