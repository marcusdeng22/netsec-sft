
from hashlib import sha256

# generates a hash from a secret key and IV/cryptoblock
def genOTP(secret_key, extra_block, BLOCK_SIZE_BYTES):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.digest()[:BLOCK_SIZE_BYTES]

# XORs two bytes objects together
def XOR_bytes(secret_key, prebytes):
    
    # Make the key the same length as the final block.
    if len(secret_key) > len(prebytes):
        secret_key = secret_key[:len(prebytes)]

    postbytes = bytearray()
    for b1, b2 in zip(secret_key, prebytes):
        postbytes.append(b1 ^ b2)
        
    return bytes(postbytes)

# Continually generates a hash from byte strings
def integrity_hasher(BLOCK_SIZE_BYTES):
    h = sha256()
    while True:
        input_bytes = yield
        h.update(input_bytes)
        yield h.digest()[:BLOCK_SIZE_BYTES]
    # We only need to send the digest at the end of the message.
    # Generator functions maintain state, so this should result in a digest
    #   of the entire file :)
