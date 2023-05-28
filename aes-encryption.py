#!/usr/bin/python
#
# A simple script to encrypt images using AES
# with ECB, CBC, and CFB
#
# Author: Harmon Transfield
##

import sys, getopt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


IMAGE_HEADER_BYTES = 64
"""Constant.

The first 64 bytes contain the image file header and are skipped.

"""

class AESEncryptor:
    """Custom AES Encryption Class.

    This class encrypts data using AES

    Code for this assignment took inspiration from the following sources:
        https://gist.github.com/lopes/168c9d74b988391e702aac5f4aa69e41
        https://samsclass.info/141/proj/pCH-ECB.htm
        https://github.com/pakesson/diy-ecb-penguin/blob/master/encrypt_image.py
        https://www.tutorialspoint.com/python/python_command_line_arguments.htm
        https://gist.github.com/crmccreary/5610068
    """

    def __init__(self, key):
        """Initialises an AESEncryptor Instance.

        Args:
            key: A fixed key (128 bit) is hexidecimal format.
        """
        self.key = key


    def encrypt(self, plaintext, mode, iv=""):
        """

        Raises:
            ValueError: The program cannot read file data or th
        """
        try:
            modulus = len(plaintext) % AES.block_size
            trimmed = plaintext[IMAGE_HEADER_BYTES:-modulus]

            if iv == "":
                cipher = AES.new(self.key, mode)
            else:
                cipher = AES.new(self.key, mode, iv)

            ciphertext = cipher.encrypt(trimmed)
            return plaintext[0:IMAGE_HEADER_BYTES] + ciphertext + plaintext[-modulus:]
        except ValueError:
            print(f"Input data cannot be empty!")


if __name__ == '__main__':
    """Main method.

    Entry point into the program. The program uses AES encryption for
    encrypting an image whose size is larger than the AES block size.

    Raises:
        GetOptError: An error occurred entering an invalid CLI option.
        FileNotFoundError: An error occured finding the input file.
    """
    iv = get_random_bytes(AES.block_size)
    inputfile = ''

    try:
        opts, args = getopt.getopt(sys.argv[1:],"hi:",["inputfile="])

        for opt, arg in opts:
            if opt == '-h':
                print ('aes-encryption.py -i <inputfile>')
                sys.exit()

            elif opt in ("-i", "--inputfile"):
                inputfile = arg



        with open(inputfile, "rb") as img:
            # instantiate a new AESEncryptor object
            aes = AESEncryptor('770A8A65DA156D24EE2A093277530142'.encode("utf8"))
            plaintext = img.read()

            # generate ciphertext for each mode of operation
            ecb_cipher = aes.encrypt(plaintext, AES.MODE_ECB)
            cbc_cipher = aes.encrypt(plaintext, AES.MODE_CBC, iv)
            cfb_cipher = aes.encrypt(plaintext, AES.MODE_CFB, iv)

            # write encrypted ECB bytes to a JPG image file
            with open("ecb.jpg", "wb") as f:
                f.write(ecb_cipher)

            # write encrypted CBC bytes to a JPG image file
            with open("cbc.jpg", "wb") as f:
                f.write(cbc_cipher)

            # write encrypted CFB bytes to a JPG image file
            with open("cfb.jpg", "wb") as f:
                f.write(cfb_cipher)

    except getopt.GetoptError:
        print(f"option -%s not recognised", opt)

    except FileNotFoundError as fnfe:
        print(f"File {inputfile} not found!", file=sys.stderr)
