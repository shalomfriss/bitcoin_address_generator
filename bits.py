# The curve bitcoin uses (secp256k1) is y^2 == x^3 + 7   ( mod p )  where p = 2^256 - 2^32 - 977
# a point (x,y) is on the curve if it matches the above equation

from fastecdsa import keys, curve
import sys, hashlib
from binascii import hexlify, unhexlify


__zeros = '0000000000000000000000000000000000000000000000000000000000000000'
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


def b58encode(v):
  long_value = 0L
  for (i, c) in enumerate(v[::-1]):
    long_value += (256**i) * ord(c)
  result = ''
  while long_value >= __b58base:
    div, mod = divmod(long_value, __b58base)
    result = __b58chars[mod] + result
    long_value = div
  result = __b58chars[long_value] + result
  nPad = 0
  for c in v:
    if c == '\0': nPad += 1
    else: break
  return (__b58chars[0]*nPad) + result
  
    
def main():
    
    # First we generate private key
    priv_key = keys.gen_private_key(curve.secp256k1)
    print "Private key: " + str(priv_key)
    
    # Next we generate a public key
    pub_key = keys.get_public_key(priv_key, curve.secp256k1)
    print "Public key: " + str(pub_key)
    
    # Now we generate a bitcoin address
    rpmd160hash = hashlib.new('ripemd160')
    formattedPubKey = '\x04'+str(pub_key.x)+str(pub_key.y)
    rpmd160hash.update(hashlib.sha256(formattedPubKey).digest())
    print "Hash 160: " + str('\x00'+rpmd160hash.digest())
    btcAddress = '\x00'+rpmd160hash.digest()
    
    chksum = hashlib.sha256(hashlib.sha256(btcAddress).digest()).digest()[:4]
    btcAddress = b58encode(btcAddress+chksum)
    
    formattedPubKey = hexlify(formattedPubKey)
    formattedPrivKey = hexlify(str(priv_key))
    formattedPrivKey = '80'+__zeros[0:64-len(formattedPrivKey)]+formattedPrivKey
    formattedPrivKey = unhexlify(formattedPrivKey)
    
    chksum = hashlib.sha256(hashlib.sha256(formattedPrivKey).digest()).digest()[:4]
    formattedPrivKey = b58encode(formattedPrivKey+chksum)
    print (btcAddress,formattedPrivKey, formattedPubKey)
      
    
if __name__== "__main__":
  main()