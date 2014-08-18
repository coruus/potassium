"""A simple implementation of exponential-length padding, using the MBR padding
   construction.

   Linear padding leaks an unbounded amount of information; this doesn't.
   See, e.g., Goldreich vol. 1.

   The minimum message size should be set to something reasonably large; 2050
   bytes is good for most purposes (it base64-encodes with no padding).

   License: 3BSD
"""
from __future__ import division, print_function

EXLENGTH = 2049


def expad_length(length):
  """Calculate the padded length of a message."""
  if length < EXLENGTH:
    return EXLENGTH
  else:
    padded_len = 2048
    while length > padded_len:
      padded_len <<= 1
    return padded_len + 1

def pad(message):
  """Expad a message."""
  message_len = len(message)
  padded_len = expad_length(message_len)
  padlen = padded_len - message_len
  mbrpad = bytearray([0x00] * padlen)
  mbrpad[0] = 0x01
  # Note that the XOR is important; the padding may only be
  # a single byte in length.
  mbrpad[-1] ^= 0x80
  return bytes(bytearray().join([message, mbrpad]))


def unpad(message):
  """Unpad an expadded message."""
  message = bytearray(message)
  if message[-1] & 0x80 == 0:
    return None
  message[-1] ^= 0x80
  i = len(message) - 1
  while message[i] != 0x01:
    i -= 1
  return bytes(message[:i])


def test_pad(message='this is a test'):
  """Test ex-padding."""
  return unpad(pad(message)) == message


def test_pad_exhaustive():
  """Exhaustively test ex-padding."""
  for i in range(EXLENGTH * 32):
    message = 'a' * i
    if unpad(pad(message)) != message:
      return False
  return True

assert test_pad() == True
