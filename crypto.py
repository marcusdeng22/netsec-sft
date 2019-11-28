
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
    return bytes(ret)

# generates a 16 byte hash from a secret key and IV/cryptoblock
def genOTP(secret_key, extra_block):
    h = sha256()
    h.update(secret_key)
    h.update(extra_block)
    return h.digest()[:8]

# XORs two bytes objects together
def crypticate(secret_key, prebytes):
    # Make the key the same length as the final block.
    if len(secret_key) > len(prebytes):
        secret_key = secret_key[:len(prebytes)]

    postbytes = bytearray()
    for b1, b2 in zip(secret_key, prebytes):
        postbytes.append(b1 ^ b2)
        
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
                    cipherbytes = crypticate(key_block, from_file)

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
                key_block = genOTP(SECRET_KEY, cipherbytes)
    
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


    # Authentication failure check
    if len(buff) == 0:
        return False

    # Otherwise, deal with the last less-than-block_size bytes of data
    # Get the actual leftover number of data bytes pertaining to the message.
    num_bytes = num_bytes % block_size_bytes

    # Break apart the message bytes from the hash bytes
    cryptbytes, hashbytes = buff[:num_bytes], buff[num_bytes:]

    # Decrypt the message bytes
    plainbytes = crypticate(key_block, cryptbytes)
    decryptedData += plainbytes

    # Final data hash
    next(h)
    integrity_hash = h.send(plainbytes)

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
