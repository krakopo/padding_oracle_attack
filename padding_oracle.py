#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class PaddingOracle:

  def __init__(self, block_size=16):
    self.block_size = 16
    key = os.urandom(32)
    iv = os.urandom(block_size)

    self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

  def encrypt(self, msg):
    print('Message to encrypt: {}'.format(msg))

    padder = padding.PKCS7(self.block_size).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    print('Padded message: {}'.format(padded_msg))

    encryptor = self.cipher.encryptor()
    cipher_text = encryptor.update(padded_msg) + encryptor.finalize()
    print('Encrypted message: {}'.format(cipher_text))

    return cipher_text

  def decrypt(self, cipher_text):
    print('Cipher text to decrypt: {}'.format(cipher_text))

    decryptor = self.cipher.decryptor()
    padded_msg = decryptor.update(cipher_text) + decryptor.finalize()
    print('Padded message: {}'.format(padded_msg))

    unpadder = padding.PKCS7(self.block_size).unpadder()
    msg = unpadder.update(padded_msg) + unpadder.finalize()
    print('Decrypted message: {}'.format(msg))

    return msg

# Example usage:
#
# p = PaddingOracle()
# ct = p.encrypt(b"secret message")
# msg = p.decrypt(ct)
# msg = p.decrypt(b'a'*16) # Throws invalid padding bytes
