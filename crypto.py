
from hashlib import sha256

def genOTP(secret_key, extra_block):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.hexdigest()[:16]


# Receive a bytes object, plainbytes.
# Bitshift-buildup each int-elem in plainbytes into a single integer.
# XOR that with the secret key.
# Bitshift-breakdown the integer down into a list of int-elems.
# Turn the result back into a bytes object, cipherbytes.
def encrypt(secret_key, plainbytes, shift=0):
    num_bytes = len(plainbytes)
    block_size_bytes = num_bytes + shift
    
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
    
    #print('\nUnencrypted integer:\n {0:0>{1}b}'.format(unencrypted_int, block_size_bytes*8))
    #print()

    # Encrypt it by XOR'ing it with the key.
    encrypted_int = unencrypted_int ^ secret_key
    # print('\nEncrypted integer:\n{0:0>{1}b}'.format(encrypted_int, block_size_bytes*8))
    # print()

    # Break down the encrypted integer into a list of individual ints (so we can
    # convert it back into a bytes object).
    int_list = []
    for i in range(num_bytes):
        # Take the 8 LSB and insert it at front of list
        lsb = 0b11111111 & encrypted_int
        int_list.insert(0, lsb)
        #print('{a:0{b}b} {c:08b} {d}\n'.format(a=encrypted_int, b=(block_size_bytes*8)-(i*8), c=lsb, d=int_list[0]))
        encrypted_int >>= 8  # Until decrypted_int is no more

    # Convert list_int into a bytes object. Each integer in the list literally becomes
    # an integer in the bytes object.
    cipherbytes = bytes(int_list)
    # for byte in cipherbytes:
    #     print('{0:08b}'.format(byte))
    # print(cipherbytes)

    return cipherbytes


# Receive a bytes object, cipherbytes.
# Bitshift-buildup each int-elem in cipherbytes into a single integer.
# XOR that with the secret key.
# Bitshift-breakdown the integer down into a list of int-elems.
# Turn the result back into a bytes object, plainbytes.
def decrypt(secret_key, cipherbytes, shift=0):
    num_bytes = len(cipherbytes)
    block_size_bytes = num_bytes + shift

    # Destroy the key until its length is the same as the final block length.
    # Technically this is conditional on whether we are on the last block, but
    #   it's a one-liner so this will probably be more efficient.
    secret_key >>= shift*8
    #print('temp_sec_key: {0:0>{1}b}'.format(temp_sec_key, num_bytes*8))
    
    # Convert it into a proper integer bitstring.
    unencrypted_int = 0
    for idx, byte in enumerate(cipherbytes):
        unencrypted_int = (unencrypted_int << 8) | byte
        #print('{a:0{b}b} {c:08b} {d}'.format(a=unencrypted_int, b=idx*8, c=byte, d=byte))
    
    # Decrypt it by XOR'ing it with the key.
    decrypted_int = unencrypted_int ^ secret_key
    #print('Decrypted integer: {0:0>{1}b}'.format(decrypted_int, block_size_bytes*8))

    # Break down the decrypted integer into a list of individual ints (so we can
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
