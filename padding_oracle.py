#!/usr/bin/env python3

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# Example usage:
#
# p = PaddingOracle()
#
# ct = p.encrypt(b"secret message")
#
# msg = p.decrypt(ct)
#
# msg = p.decrypt(b'a'*16) # Throws invalid padding bytes
#
class PaddingOracle:

  def __init__(self):
    # block size in bytes
    self.block_size = int(algorithms.AES.block_size / 8)
    self.key = os.urandom(32)

  def encrypt(self, msg, verbose=False):
    iv = os.urandom(self.block_size)
    cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))

    if verbose:
      print('Message to encrypt: {}'.format(msg))

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_msg = padder.update(msg) + padder.finalize()
    if verbose:
      print('Padded message: {}'.format(padded_msg))

    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_msg) + encryptor.finalize()
    if verbose:
      print('Encrypted message: {}'.format(cipher_text))

    # Reciever doesn't always have our IV so we must send it with cipher text
    # Reciever _will_ have the key though
    return iv + cipher_text

  def decrypt(self, iv_cipher_text, verbose=False):
    iv = iv_cipher_text[0:self.block_size]
    cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
    cipher_text = iv_cipher_text[self.block_size:]

    if verbose:
      print('Cipher text to decrypt: {}'.format(cipher_text))

    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(cipher_text) + decryptor.finalize()
    if verbose:
      print('Padded message: {}'.format(padded_msg))

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    msg = unpadder.update(padded_msg) + unpadder.finalize()
    if verbose:
      print('Decrypted message: {}'.format(msg))

    return msg

