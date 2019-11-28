
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

# XORs two bytes objects together
def XOR_bytes(byte1, byte2):
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

# reads a file and sends it as an encrypted bytestring and sends an integrity hash
# returns True if successful, False if file does not exist
def send_file(fileName, SECRET_KEY, INTEGRITY_KEY, key_block, block_size_bytes, s):
    try:
        with open(fileName, 'rb') as file:
            h = integrity_hasher()

            while True:
                # Read block_size bytes from the file.
                from_file = file.read(block_size_bytes)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.
                num_bytes = len(from_file)

                # Dump the plainbytes into the integrity hash
                next(h)
                integrity_hash = h.send(from_file)

                # If end of file,
                if num_bytes < block_size_bytes:
                    # Only XOR as much of the key as there is message.
                    shift = block_size_bytes - num_bytes
                    cipherbytes = crypticate(key_block, from_file, shift)

                    key_block = '{0:x}'.format(key_block)[:num_bytes*2]
                    # Send the last of the encrypted message
                    s.sendall(cipherbytes)

                    # Throw in the secret integrity key and send it off
                    next(h)
                    integrity_hash = h.send(INTEGRITY_KEY)
                    s.sendall(integrity_hash)
                    return True

                # else, process one block of bytes at a time.
                cipherbytes = crypticate(key_block, from_file)

                # Send over network.
                s.sendall(cipherbytes)

                # Generate a block of secret passkey
                key_block = genOTP(SECRET_KEY, cipherbytes)  # Receive a hex string using the ciper block we just created
                key_block = int(key_block, 16)  # Create an integer
    
    except FileNotFoundError:
        return False

# writes to a file if successful decryption and matching integrity hash
# returns True if successful write, False otherwise
# does not remove the file on failure
def recv_file(fileName, SECRET_KEY, INTEGRITY_KEY, key_block, block_size_bytes, conn):
    h = integrity_hasher()
    integrity_hash = ''

    # maintain two vars, 'buff' and 'incoming'.
    #   recv'ing into 'incoming' instead of immediately appending to
    #       'buff' allows us to check for empty string.
    #   appending to 'buff' instead of immediately recv'ing to 'buff'
    #       allows us to maintain any bytes leftover from while loop
    #       when len(buff) < block_size.

    buff = ''.encode('utf-8')
    # Initialized outside of loop so we can
    #   1. append to it inside of the loop,
    #   2. deal with last less-than-block_size bytes of data after loop.
    decryptedData = "".encode("utf-8")

    while True:
        incoming = conn.recv(1024)

        # if we recv'd empty string, client closed connection,
        if not incoming:
            break  # so break from loop.
            # buff will be less than block_size bytes b/c while loop.

        # else, continue processing data

        buff += incoming

        # Want at least block_size bytes to XOR with our key.
        num_bytes = len(buff)
        while num_bytes >= block_size_bytes*2:
            # Can lookahead for the integrity hash by consuming until *2
            # Note that this requires the block size and integrity hash to
            #   be of the same length. Could make it more flexible by multiplying
            #   by however many times larger the integrity hash is, but then
            #   on the last block we'd need to consider the case in which the
            #   hash is smaller, and honestly we're going for simplicity here.

            # Receive a block of encrypted bytes.
            encrypted_bytes, buff = buff[:block_size_bytes], buff[block_size_bytes:]
            num_bytes -= block_size_bytes

            plainbytes = crypticate(key_block, encrypted_bytes)
            decryptedData += plainbytes

            next(h)
            integrity_hash = h.send(plainbytes)

            key_block = genOTP(SECRET_KEY, encrypted_bytes)
            key_block = int(key_block, 16)


    # Authentication failure check
    if len(buff) == 0:
        return False

    # Otherwise, deal with the last less-than-block_size bytes of data
    # Get the actual leftover number of data bytes pertaining to the message.
    num_bytes = num_bytes % block_size_bytes

    # Break apart the message bytes from the hash bytes
    cryptbytes, hashbytes = buff[:num_bytes], buff[num_bytes:]

    # Decrypt the message bytes
    shift = block_size_bytes - num_bytes
    plainbytes = crypticate(key_block, cryptbytes, shift)
    decryptedData += plainbytes

    # Final data hash
    next(h)
    integrity_hash = h.send(plainbytes)

    key_block = '{0:x}'.format(key_block)[:num_bytes*2]

    next(h)
    integrity_hash = h.send(INTEGRITY_KEY)
    for i in range(len(integrity_hash)):
        if integrity_hash[i] != hashbytes[i]:
            return False

    # write out data
    try:
        with open(fileName, "wb") as file:
            file.write(decryptedData)
    except:
        return False
    return True
