"""A randomized authenticated encryption mode using the encrypt-then-MAC
   construction, using deniable key exchange on djb's Curve25519.

   It is primarily intended for use with Pythonista on iOS, which supports
   AES encryption via PyCrypto; it does work, however, with any version
   of Python.

   The code for scalar multiplication using a Montgomery ladder is based
   on Matt Dempsey's, in the NaCl crypto paper.

   Note that no provisions for defense against side-channel attacks have been
   made. It is assumed that this code will be used interactively; it is unsafe
   for automated use.

   License: CC0 with attribution kindly requested
"""

from __future__ import division, print_function

from base64 import urlsafe_b64encode as b64e
from base64 import urlsafe_b64decode as b64d

from hashlib import sha512
from hmac import HMAC
from os import urandom
from os.path import exists

from Crypto.PublicKey.pubkey import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util import Counter

from expad import pad, unpad

# TODO(dlg): Use bytes_to_long and long_to_bytes

#--Curve25519--

P = 2 ** 255 - 19
A = 486662

def expmod(b, e, m):
  if e == 0:
      return 1
  t = expmod(b, e // 2, m) ** 2 % m
  if e & 1:
      t = (t * b) % m
  return t


def inv(x):
  return expmod(x, P - 2, P)


def add((xn,zn), (xm,zm), (xd,zd)):
  x = 4 * (xm * xn - zm * zn) ** 2 * zd
  z = 4 * (xm * zn - zm * xn) ** 2 * xd
  return (x % P, z % P)


def double((xn,zn)):
  x = (xn ** 2 - zn ** 2) ** 2
  z = 4 * xn * zn * (xn ** 2 + A * xn * zn + zn ** 2)
  return (x % P, z % P)


def curve25519(n, base):
  one = (base,1)
  two = double(one)
  # f(m) evaluates to a tuple
  # containing the mth multiple and the
  # (m+1)th multiple of base.
  def f(m):
    if m == 1:
        return (one, two)
    (pm, pm1) = f(m // 2)
    if (m & 1):
      return (add(pm, pm1, one), double(pm1))
    return (double(pm), add(pm, pm1, one))
  ((x,z), _) = f(n)
  return (x * inv(z)) % P


def unpack(s):
  if len(s) != 32:
    raise ValueError("Invalid Curve25519 argument")
  return sum(ord(s[i]) << (8 * i) for i in range(32))


def pack(n):
  return "".join([chr((n >> (8 * i)) & 255) for i in range(32)])


def clamp(n):
  """Clamp a public key on Curve25519"""
  n &= ~7
  n &= ~(128 << 8 * 31)
  n |= 64 << 8 * 31
  return n


def crypto_scalarmult_curve25519(n, p):
  n = clamp(unpack(n))
  p = unpack(p)
  return pack(curve25519(n, p))


def crypto_scalarmult_curve25519_base(n):
  n = clamp(unpack(n))
  return pack(curve25519(n, 9))


def test_curve25519():
  """Test Curve25519 scalar multiplication. Test-vector from naclcrypto"""
  sk = [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
        0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a]
  n = "".join([chr(sk[i]) for i in range(32)])
  pk = [0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
        0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a]
  s = "".join([chr(pk[i]) for i in range(32)])
  return s == crypto_scalarmult_curve25519_base(n)


def curve25519_random_keypair():
  """Generate a random Curve25519 keypair"""
  sk = urandom(32)
  pk = crypto_scalarmult_curve25519_base(sk)
  return sk, pk


def curve25519_new_keypair():
  """Generate a base64-encoded Curve25519 keypair"""
  sk, pk = curve25519_random_keypair()
  return b64e(sk), b64e(pk)


#--Curve25519-KDF(HMAC-SHA512)-AES256-CTR-HMAC-SHA512--

def kdf_sha512(key, message):
  """Derive two 32-byte keys using HMAC-SHA512"""
  key = HMAC(key, msg=message, digestmod=sha512).digest()
  return key[:32], key[32:]


def curve25519_aes_ctr_hmac_sha512_encrypt(recipient_key, message):
  """Randomized encryption using Curve25519-AES256-HMAC-SHA512

     recipient_key: the recipient's public Curve25519 key in base64
     message: the message to encrypt
  """
  pk = b64d(recipient_key)
  e_sk, e_pk = curve25519_random_keypair()
  shared_secret = crypto_scalarmult_curve25519(e_sk, pk)
  nonce = urandom(32)
  authkey, enckey = kdf_sha512(shared_secret, nonce)
  cipher = AES.new(enckey, mode=AES.MODE_CTR, counter=Counter.new(128))
  ciphertext = cipher.encrypt(pad(message))
  mac = HMAC(authkey, ciphertext, digestmod=sha512).digest()
  return b64e(''.join([nonce, e_pk, ciphertext, mac]))


def curve25519_aes_ctr_hmac_sha512_decrypt(secret_key, message):
  """Decryption of Curve25519-AES256-HMAC-SHA512

     secret_key: the recipient's secret Curve25519 key in base64
     message: the message to authenticate and decrypt
  """
  sk = b64d(secret_key)
  msg = b64d(message)
  nonce, e_pk, ciphertext, mac = msg[:32], msg[32:64], msg[64:-64], msg[-64:]
  shared_secret = crypto_scalarmult_curve25519(sk, e_pk)
  authkey, enckey = kdf_sha512(shared_secret, nonce)
  computed_mac = HMAC(authkey, ciphertext, digestmod=sha512).digest()
  if computed_mac != mac:
      return None
  cipher = AES.new(enckey, mode=AES.MODE_CTR, counter=Counter.new(128))
  plaintext = unpad(cipher.decrypt(ciphertext))
  return plaintext


keypair = curve25519_new_keypair
encrypt = curve25519_aes_ctr_hmac_sha512_encrypt
decrypt = curve25519_aes_ctr_hmac_sha512_decrypt


def test_encdec(message='this is a test of a short message'):
  sk, pk = keypair()
  c = encrypt(pk, message)
  p = decrypt(sk, c)
  return p == message


def write_keypair(filename='id_curve25519'):
  sk, pk = keypair()
  if exists(filename):
    print("%s exists. Not overwriting".format(filename))
  with open(filename, 'wb') as f:
    f.write(sk)
  with open(filename + '.pub', 'wb') as f:
   f.write(pk)


def decrypt_withkeyfile(message, filename='id_curve25519'):
  with open(filename, 'rb') as f:
    sk = f.read()
  return decrypt(sk, message)


#--test things are working right--
assert test_curve25519() == True
assert test_encdec() == True
