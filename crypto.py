
from hashlib import sha256


def integrity_hasher():
    h = sha256()
    while True:
        input_bytes = yield
        h.update(input_bytes)
        yield h.digest()[:8]
    # We only need to send the digest at the end of the message.
    # Generator functions maintain state, so this should result in a digest
    #   of the entire file :)


def genOTP(secret_key, extra_block):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.hexdigest()[:16]


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
    #print('sec_key: {0:0>{1}b}'.format(sec_key, num_bytes*8))

    # Convert the prebytes into a proper integer bitstring.
    pre_int = 0
    for idx, byte in enumerate(prebytes):
        pre_int = (pre_int << 8) | byte
        #print('{a:0{b}b} {c:08b} {d}'.format(a=pre_int, b=idx*8, c=byte, d=byte))
    
    #print('\pre_int:\n {0:0>{1}b}'.format(unencrypted_int, block_size_bytes*8))
    #print()

    # Encrypt/Decrypt it by XOR'ing it with the key.
    post_int = pre_int ^ secret_key
    # print('\post_int:\n{0:0>{1}b}'.format(post_int, block_size_bytes*8))
    # print()

    # Break down the integer into a list of individual ints (so we can
    # convert it back into a bytes object).
    int_list = []
    for i in range(num_bytes):
        # Take the 8 LSB and insert it at front of list
        lsb = 0b11111111 & post_int
        int_list.insert(0, lsb)
        #print('{a:0{b}b} {c:08b} {d}\n'.format(a=post_int, b=(block_size_bytes*8)-(i*8), c=lsb, d=int_list[0]))
        post_int >>= 8  # Until post_int is no more

    # Convert list_int into a bytes object. Each integer in the list literally
    # becomes an integer in the bytes object.
    postbytes = bytes(int_list)
    # for byte in postbytes:
    #     print('{0:08b}'.format(byte))
    # print(postbytes)

    return postbytes
