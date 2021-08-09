#!/usr/bin/env python3

from padding_oracle import PaddingOracle

if __name__ == '__main__':
  # Encrypt a message
  p = PaddingOracle()
  c = p.encrypt(b"a secret message 1234", verbose=True)

  # Now decrypt that message not using the 'decrypt' method on the cipher text.
  # This simulates what an attacker could do to decrypt a message.

  c_no_iv = c[16:]
  numblocks = int(len(c_no_iv) / p.block_size)
  pt = []
  # Iterate over blocks from last to first
  for n in range(numblocks):
    c_n_start = len(c_no_iv) - (16 * (n + 1))
    c_n = c_no_iv[c_n_start:c_n_start + 16]
    c_n_minus_one = c_no_iv[c_n_start - 16:c_n_start]
    if len(c_n_minus_one) ==  0:
      c_n_minus_one = c[0:16]

    z_iv = bytearray(16)

    # Iterate over bytes of block from last to first
    for b in range(15, -1, -1):

      p_iv = [(16 - b) ^ z for z in z_iv]
      for i in range(256):

        p_iv[b] = i
        try:
          p.decrypt(bytes(p_iv) + c_n)
        except ValueError:
          continue

        # Handle edge case where we think we got valid 0x01 padding in last
        # byte but it was actually something else.
        if b == 15:
          p_iv[b - 1] ^= 1
          try:
            p.decrypt(bytes(p_iv) + c_n)
          except ValueError:
            continue

        z_iv[b] = i ^ (16 - b)
        break

    pt = [ chr(i ^ z) for i,z in zip(c_n_minus_one, z_iv) ] + pt

  print('Plain text decrypted using padding oracle: {}'.format(repr(''.join(pt))))

  # Compare decrypted message with what 'decrypt' method returns
  msg = p.decrypt(c, verbose=True)
