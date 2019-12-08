
from crypto import integrity_hasher, XOR_bytes, genOTP

# reads a file and sends it as an encrypted bytestring and sends an integrity hash
# returns True if successful, False if file does not exist
def send_file(fileName, SECRET_KEY, IV, BLOCK_SIZE_BYTES, s):

    # Create integrity key from received secret key + 1
    INTEGRITY_KEY = bytearray(SECRET_KEY)
    INTEGRITY_KEY[BLOCK_SIZE_BYTES-1] += 1
    INTEGRITY_KEY = bytes(INTEGRITY_KEY)
    
    # Generate first block of OTP
    key_bytes = genOTP(SECRET_KEY, IV, BLOCK_SIZE_BYTES)

    try:
        with open(fileName, 'rb') as file:
            h = integrity_hasher(BLOCK_SIZE_BYTES)

            while True:
                # Read block_size bytes from the file.
                from_file = file.read(BLOCK_SIZE_BYTES)
                    # Result is a bytes-like object of x bytes, though each element
                    # is an int already.
                num_bytes = len(from_file)
                print(from_file)

                # Dump the plainbytes into the integrity hash
                next(h)
                h.send(from_file)

                # If end of file,
                if num_bytes < BLOCK_SIZE_BYTES:
                    # Only XOR as much of the key as there is message.
                    cipherbytes = XOR_bytes(key_bytes, from_file)

                    # Send the last of the encrypted message
                    s.sendall(cipherbytes)

                    # Throw in the secret integrity key and send it off
                    next(h)
                    integrity_hash = h.send(INTEGRITY_KEY)
                    s.sendall(integrity_hash)
                    return True

                # else, process one block of bytes at a time.
                cipherbytes = XOR_bytes(key_bytes, from_file)

                # Send over network.
                s.sendall(cipherbytes)

                # Generate a block of secret passkey
                key_bytes = genOTP(SECRET_KEY, cipherbytes, BLOCK_SIZE_BYTES)
    
    except FileNotFoundError:
        return False


# writes to a file if successful decryption and matching integrity hash
# returns True if successful write, False otherwise
# does not remove the file on failure
def recv_file(fileName, SECRET_KEY, IV, BLOCK_SIZE_BYTES, conn):
    h = integrity_hasher(BLOCK_SIZE_BYTES)
    integrity_hash = ''
    
    # Create an integrity key from secret key + 1
    INTEGRITY_KEY = bytearray(SECRET_KEY)
    INTEGRITY_KEY[BLOCK_SIZE_BYTES-1] += 1
    INTEGRITY_KEY = bytes(INTEGRITY_KEY)

    # Generate first block of OTP
    key_bytes = genOTP(SECRET_KEY, IV, BLOCK_SIZE_BYTES)

    # maintain two vars, 'buff' and 'incoming'.
    #   recv'ing into 'incoming' instead of immediately appending to
    #       'buff' allows us to check for empty string.
    #   appending to 'buff' instead of immediately recv'ing to 'buff'
    #       allows us to maintain any bytes leftover from while loop
    #       when len(buff) < block_size.

    buff = bytearray()
    # Initialized outside of loop so we can
    #   1. append to it inside of the loop,
    #   2. deal with last less-than-block_size bytes of data after loop.
    
    with open(fileName, "wb") as file:
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
            while num_bytes >= BLOCK_SIZE_BYTES*2:
                # Can lookahead for the integrity hash by consuming until *2
                # Note that this requires the block size and integrity hash to
                #   be of the same length. Could make it more flexible by multiplying
                #   by however many times larger the integrity hash is, but then
                #   on the last block we'd need to consider the case in which the
                #   hash is smaller, and honestly we're going for simplicity here.

                # Receive a block of encrypted bytes.
                encrypted_bytes, buff = buff[:BLOCK_SIZE_BYTES], buff[BLOCK_SIZE_BYTES:]
                num_bytes -= BLOCK_SIZE_BYTES

                plainbytes = XOR_bytes(key_bytes, encrypted_bytes)
                print(plainbytes)
                file.write(plainbytes)

                next(h)
                h.send(plainbytes)

                key_bytes = genOTP(SECRET_KEY, encrypted_bytes, BLOCK_SIZE_BYTES)

        # Otherwise, deal with the last less-than-block_size bytes of data
        # Get the actual leftover number of data bytes pertaining to the message.
        num_bytes = num_bytes % BLOCK_SIZE_BYTES

        # Break apart the message bytes from the hash bytes
        cryptbytes, hashbytes = buff[:num_bytes], buff[num_bytes:]

        # Decrypt the message bytes
        plainbytes = XOR_bytes(key_bytes, cryptbytes)
        print(plainbytes)
        file.write(plainbytes)

    # Final data hash
    next(h)
    h.send(plainbytes)

    next(h)
    integrity_hash = h.send(INTEGRITY_KEY)
    if integrity_hash != hashbytes:
        print("Integrity failure")
        return False
    return True
