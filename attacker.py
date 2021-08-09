#!/usr/bin/env python3

# Proof of concept for a padding oracle attack as outlined here:
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/

from padding_oracle import PaddingOracle

if __name__ == '__main__':
  # Encrypt a message
  p = PaddingOracle()
  c = p.encrypt(b"a secret message 1234", verbose=True)
  #c = p.encrypt(b"1234", verbose=True)

  # Now decrypt that message not using the 'decrypt' method on the cipher text.
  # This simulates what an attacker could do to decrypt a message.

  # Get number of blocks to decrypt.
  # Subtract one for first block which is the initialization vector (IV).
  # No need to decrypt the IV.
  num_blocks = int(len(c) / p.block_size) - 1

  # Where we will store the plain text message as we decrypt
  plain_text = []

  # Iterate over blocks from last to first
  for n in range(num_blocks):
    # Index of where this block starts
    block_start = len(c) - 16 * (n + 1)
    # The current block
    curr_block = c[block_start:block_start + 16]
    # The previous block
    prev_block = c[block_start - 16:block_start]

    # The zeroing IV.
    # We will determine the value of this IV using brute force and the padding oracle.
    # This IV has the property: IV xor BLOCK = 0 (Hence the name, zeroing IV).
    # Doesn't this just mean IV = BLOCK? Yes, but we don't know the value of BLOCK.
    #
    # Recall that the IV is xor'd with the decrypted bytes in order to get the plain text.
    # So if we have an IV such that IV xor decrypted bytes = 0, then we know the value of
    # the decrypted blocks! (It's equal to IV).
    z_iv = bytearray(16)

    # Iterate over bytes of block from last to first
    for b in range(15, -1, -1):

      p_iv = [(16 - b) ^ z for z in z_iv]
      for i in range(256):

        p_iv[b] = i
        try:
          p.decrypt(bytes(p_iv) + curr_block)
        except ValueError:
          continue

        # Handle edge case where we think we got valid 0x01 padding in last
        # byte but it was actually something else.
        if b == 15:
          p_iv[b - 1] ^= 1
          try:
            p.decrypt(bytes(p_iv) + curr_block)
          except ValueError:
            continue

        z_iv[b] = i ^ (16 - b)
        break

    plain_text = [ chr(i ^ z) for i,z in zip(prev_block, z_iv) ] + plain_text

  print('Plain text decrypted using padding oracle: {}'.format(repr(''.join(plain_text))))

  # Compare decrypted message with what 'decrypt' method returns
  msg = p.decrypt(c, verbose=True)
