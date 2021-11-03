#!/usr/bin/env python3

# Proof of concept for a padding oracle attack as outlined here:
# https://research.nccgroup.com/2021/02/17/cryptopals-exploiting-cbc-padding-oracles/

from padding_oracle import PaddingOracle

if __name__ == '__main__':
  # Encrypt a message
  p = PaddingOracle()
  c = p.encrypt(b"a secret message 1234", verbose=True)

  # Now decrypt that message but not using the 'decrypt' method on the cipher text.
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

    # The zeroing initialization vector (z_iv).
    #
    # We will determine the value of z_iv using brute force and the padding oracle.
    # The z_iv has the property: z_iv xor block = 0 (Hence the name, zeroing IV).
    # Doesn't this just mean z_iv = block? Yes, but we don't know the value of block.
    #
    # In this case the block is the decrypted cipher text prior to the final
    # xor with the IV (or previous cipher block) which produces the plain text.
    # So if we have an z_iv such that z_iv xor decrypted block = 0, then we know
    # the value of the decrypted block! (It's equal to z_iv).
    #
    # With this z_iv = decrypted block, we can now simply xor it with the
    # previous cipher block (or IV if no previous cipher block) in order
    # to recover the plain text.
    #
    z_iv = bytearray(16)

    # Iterate over bytes of block from last to first
    for b in range(15, -1, -1):

      # The padding IV. This IV is what we pass into the decrypt function in
      # order to brute force the value for the zeroing IV. With the padding IV
      # we use brute force and the padding oracle to determine values which
      # will result in correct padding of the plain text. We know what the
      # padding values should be since the PKCS7 padding algorithm tells us.
      # We use the padding oracle to confirm if our padding IV guesses to
      # achieve said plain text padding values are correct.
      #
      # Why xor x_iv with (16 - b)? 16 - b is the expected padding value for
      # the current byte of the the block. For 1 byte of padding, byte 15 has
      # value 1. For 2 bytes of padding, bytes 15 and 14 have value 2.
      # For 3 bytes of padding, bytes 15, 14 and 13 have value 3. And so on.
      # The xor sets the plain text value to the the padding we expect.
      #
      # Note that it doesn't matter what the 0 to b-th bytes are of p_iv.
      # The b-th byte will be brute forced below. What is important is that
      # the b+1 to 16 bytes are set to the expected padding values.
      #
      p_iv = [(16 - b) ^ z for z in z_iv]

      # Brute force phase. Here we iterate over all possible byte values [0, 255]
      # for the b-th byte of the block. We modify p_iv each time and stop when
      # we arrive at a valid padding.
      #
      for i in range(256):

        p_iv[b] = i

        # Now use the padding oracle to check the padding
        try:
          p.decrypt(bytes(p_iv) + curr_block)
        except ValueError:
          # Continue with brute force search if the padding is invalid
          continue

        # Handle edge case where we think we got valid 0x01 padding in last
        # byte but it was actually something else.
        if b == 15:
          # Flip last bit of byte b-1 of p_iv and recheck the padding.
          # If the padding is invalid, we knew there was a dependency on the
          # value of the b-1 byte which means our value in byte b was not
          # sufficient to control the padding value of the plain text.
          p_iv[b - 1] ^= 1
          try:
            p.decrypt(bytes(p_iv) + curr_block)
          except ValueError:
            continue

        # Update zeroing IV with the value we found
        z_iv[b] = i ^ (16 - b)

        # We found the value we're looking for
        break

    # We now have the full zeroing IV and can recover the plain text value
    # for the current block.
    plain_text = [ chr(i ^ z) for i,z in zip(prev_block, z_iv) ] + plain_text

  print('Plain text decrypted using padding oracle: {}'.format(repr(''.join(plain_text))))

  # Compare decrypted message with what 'decrypt' method returns
  msg = p.decrypt(c, verbose=True)
