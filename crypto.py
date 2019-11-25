
from hashlib import sha256

def byteXor(byte1, byte2):
    ret = bytearray()
    for b1, b2 in zip(byte1, byte2):
        ret.append(b1 ^ b2)
    return ret

def genOTP(secret_key, extra_block):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.hexdigest()


def encrypt(secret_key, plainbytes, num_bytes, shift=0):

    # Destroy the key until its length is the same as the length of the final block.
    # Technically this is conditional on whether we are on the last block, but
    #   it's a one-liner so this will probably be more efficient.
    secret_key >>= shift*8
    #print('sec_key: {0:0>{1}b}'.format(sec_key, num_bytes*8))

    # Convert it into a proper integer bitstring.
    unencrypted_int = 0
    for idx, byte in enumerate(plainbytes):
        unencrypted_int = (unencrypted_int << 8) | byte
        #print('{a:0{b}b} {c:08b} {d}'.format(a=unencrypted_int, b=idx*8, c=byte, d=byte))

    #print('\nUnencrypted integer: {0:0>{1}b}'.format(unencrypted_int, block_size_bytes*8))

    # Encrypt it by XOR'ing it with the key.
    encrypted_int = unencrypted_int ^ secret_key
    #print('Encrypted integer: {0:0>{1}b}'.format(encrypted_int, block_size_bytes*8))

    # Convert it back to a string object (so we can encode it).
    # Each bit is a character.
    encrypted_bitstring = '{0:0>{1}b}'.format(encrypted_int, num_bytes*8)
    #print('Encrypted bitstring:', encrypted_bitstring)

    # Convert to bytes (to send over network).
    # Each bit is a byte.
    cipherbytes = encrypted_bitstring.encode('utf-8')
    #print("Encrypted bytes:", encrypted_bytes)

    return cipherbytes


def decrypt(secret_key, cipherbytes, num_bytes, shift=0):

    # Destroy the key until its length is the same as the final block length.
    # Technically this is conditional on whether we are on the last block, but
    #   it's a one-liner so this will probably be more efficient.
    secret_key >>= shift*8
    #print('temp_sec_key: {0:0>{1}b}'.format(temp_sec_key, num_bytes*8))

    # Decode the encrypted bytes to get a bitstring. Each character is one bit.
    encrypted_bitstring = cipherbytes.decode('utf-8')
    #print('Encrypted bitstring:', encrypted_bitstring)

    # Convert the bitstring into an integer
    encrypted_int = int(encrypted_bitstring, 2)
    #print('Encrypted integer: {0:0>{1}b}'.format(encrypted_int, block_size_bytes*8))

    # Decrypt it by XOR'ing it with the key.
    decrypted_int = encrypted_int ^ secret_key
    #print('Decrypted integer: {0:0>{1}b}'.format(decrypted_int, block_size_bytes*8))

    # Break down the integer into a list of individual ints (so we can
    # convert it back into a bytes object).
    #print()
    int_list = []
    for _ in range(num_bytes):
        # Take the 8 LSB and insert it at front of list
        lsb = 0b11111111 & decrypted_int
        int_list.insert(0, lsb)
        #print('{a:0{b}b} {c:08b} {d}'.format(a=decrypted_int, b=(block_size_bytes*8)-(i*8), c=lsb, d=int_list[0]))
        decrypted_int >>= 8  # Until decrypted_int is no more

    # Convert list_int into a bytes object.
    plainbytes = bytes(int_list)

    return plainbytes
