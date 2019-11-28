
from hashlib import sha256

# creates a 8 byte hash from part of a byte string
def integrity_hasher():
    h = sha256()
    while True:
        input_bytes = yield
        h.update(input_bytes)
        yield h.digest()[:8]
    # We only need to send the digest at the end of the message.
    # Generator functions maintain state, so this should result in a digest
    #   of the entire file :)

# xors two bytes objects together
def byteXor(byte1, byte2):
    ret = bytearray()
    for b1, b2 in zip(byte1, byte2):
        ret.append(b1 ^ b2)
    return ret

# generates a 16 byte hash from a secret key and IV
def genOTP(secret_key, extra_block):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.hexdigest()[:16]

# Acts as both an encrypt and decrypt function
# Receive a bytes object, prebytes.
# Bitshift-buildup each int-elem in prebytes into a single integer.
# XOR that with the secret key.
# Bitshift-breakdown the integer down into a list of int-elems.
# Turn the result back into a bytes object, postbytes.
def crypticate(secret_key, prebytes, shift=0):
    num_bytes = len(prebytes)
    block_size_bytes = num_bytes + shift

    # Destroy the key until its length is the same as the length of the final block.
    # Technically this is conditional on whether we are on the last block, but
    #   it's a one-liner so this will probably be more efficient than a branch.
    secret_key >>= shift*8
    # Convert the prebytes into a proper integer bitstring.
    pre_int = 0
    for idx, byte in enumerate(prebytes):
        pre_int = (pre_int << 8) | byte

    # Encrypt/Decrypt it by XOR'ing it with the key.
    post_int = pre_int ^ secret_key

    # Break down the integer into a list of individual ints (so we can
    # convert it back into a bytes object).
    int_list = []
    for i in range(num_bytes):
        # Take the 8 LSB and insert it at front of list
        lsb = 0b11111111 & post_int
        int_list.insert(0, lsb)
        post_int >>= 8  # Until post_int is no more

    # Convert list_int into a bytes object. Each integer in the list literally
    # becomes an integer in the bytes object.
    postbytes = bytes(int_list)
    return postbytes
