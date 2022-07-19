"""main.py - Implementation of SHA-256 algorithm.

The implementation here seeks to follow the FIPS specification as closely as
possible.
"""
from __future__ import annotations
from hashlib import sha256  # For testing.

# Constant parameters for SHA-256
BLOCK_SIZE = 512
BLOCK_MASK = 2**(512) - 1

WORD_SIZE = 32  # This is 'w' in the FIPS spec.
WORD_MASK = 0xFFFFFFFF


# Some sha operations
def rotr(n: int, x: int) -> int:
    """Rotate right (circular right shift)

    :param n: integer 0 <= n < w
    :param x: w-bit word

    :return: w-bit word
    """
    return ((x >> n) & WORD_MASK) | ((x << (WORD_SIZE-n)) & WORD_MASK)

def shr(n: int, x: int) -> int:
    """Right shift operation

    :param n: integer 0 <= n < w
    :param x: w-bit word

    :return: w-bit word
    """
    return (x >> n) & WORD_MASK

# SHA-256 specific functions
def ch(x: int, y: int, z: int) -> int:
    """
    :param x: 32-bit word
    :param y: 32-bit word
    :param z: 32-bit word
    :return: 32-bit word
    """
    return ((x & y) ^ (~x & z)) & WORD_MASK

def maj(x: int, y: int, z: int) -> int:
    """
    :param x: 32-bit word
    :param y: 32-bit word
    :param z: 32-bit word
    :return: 32-bit word
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & WORD_MASK

def big_sigma_0(x: int) -> int:
    """
    :param x: 32-bit word
    :return: 32-bit word
    """
    return (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)) & WORD_MASK

def big_sigma_1(x: int) -> int:
    """
    :param x: 32-bit word
    :return: 32-bit word
    """
    return (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)) & WORD_MASK

def sigma_0(x: int) -> int:
    """
    :param x: 32-bit word
    :return: 32-bit word
    """
    return (rotr(7, x) ^ rotr(18, x) ^ shr(3, x)) & WORD_MASK
    
def sigma_1(x: int) -> int:
    """
    :param x: 32-bit word
    :return: 32-bit word
    """
    return (rotr(17, x) ^ rotr(19, x) ^ shr(10, x)) & WORD_MASK


# SHA-256 constants
# SHA-256 uses a sequence of 64 constant 32-bit words.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

# Preprocessing
# - Pad the message M
# - Parse the message into message blocks.
# - set initial hash value H0

def pad_message(M: bytes) -> bytes:
    """Pad the SHA-256 message to a multiple of 512 bits.

    :param M: SHA-256 message.

    :return: Padded message, multiple of 512 bits.
    """
    # Get message bitwidth.
    l = len(M) * 8 

    # Find k, solution to l + 1 + k = 448 mod 512.
    k = (448 - (l+1)) % BLOCK_SIZE
    
    # Append bit "1" to message, followed by k zero bits,
    # then followed by 64-bit block containing l in binary.
    padded_msg = (int.from_bytes(M,'big')) << (k + 1 + 64)
    padded_msg |= (1 << (k+64))  # Add the 1
    padded_msg |= l              # Add l to the end.

    msglen = k + l + 1 + 448
    return padded_msg.to_bytes(msglen//8, 'big')

def parse_msg_blocks(padded_msg: bytes) -> list[bytes]:
    """Parse the padded message into 512-bit message blocks.

    :param padded_msg: The padded message.
    :return: array of 512-bit message blocks.
    """
    # Get the number of message blocks to parse, N
    N = ((len(padded_msg)*8) // 512)
    
    # Parse each message block.
    padded_msg = int.from_bytes(padded_msg, 'big')
    msg_blocks = []
    for i in range(N):
        blk = (padded_msg & (2**512 - 1)).to_bytes(512//8, 'big')
        msg_blocks.insert(0, blk)
        padded_msg = padded_msg >> 512

    return msg_blocks


# initial hash value
H0 = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]

# SECURE HASH ALGORITHM
# Hash a message M having length l bits.
# Uses
# - message schedule of 64 32-bit words
# - 8 working variables of 32-bits each.
# - hash value of 8 32-bit words.

def preprocess_msg(M: bytes) -> list[bytes]:
    """Preprocess a message M into a list of length 512-bits message blocks.

    :param M: The input message

    :return: A list of 512-bit blocks of the padded message.
    """
    padded_msg = pad_message(M)
    msg_blocks = parse_msg_blocks(padded_msg)
    return msg_blocks

def sha256_hash_computation(msg_blocks: list[bytes]) -> int:
    """Given the message blocks, return the SHA-256 digest.
    """
    N = len(msg_blocks)
    H = H0
    for i in range(N):
        Mi = int.from_bytes(msg_blocks[i], 'big')
        # Prepare the message schedule.
        W = []
        for t in range(64):
            if t < 16:
                # Set it to the t-th 32-bit word of Mi
                Wt = (Mi >> ((15-t)*32)) & WORD_MASK
                W.append(Wt)
            else:
                Wt = ((sigma_1(W[t-2]) +  W[t-7]  % 2**32) + (sigma_0(W[t-15]) + W[t-16] % 2**32)) % 2**32
                W.append(Wt)

        # Initialize the eight working variables with (i-1) hash value.
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]

        for t in range(64):
            T1 = (h + big_sigma_1(e) + ch(e,f,g) + K[t] + W[t]) % 2**32
            T2 = (big_sigma_0(a) + maj(a,b,c)) % 2**32
            h = g
            g = f
            f = e
            e = (d + T1) % 2**32
            d = c
            c = b
            b = a
            a = (T1 + T2) % 2**32

        H[0] = (a + H[0]) % 2**32
        H[1] = (b + H[1]) % 2**32
        H[2] = (c + H[2]) % 2**32
        H[3] = (d + H[3]) % 2**32
        H[4] = (e + H[4]) % 2**32
        H[5] = (f + H[5]) % 2**32
        H[6] = (g + H[6]) % 2**32
        H[7] = (h + H[7]) % 2**32
        
    # Once the last hash is done, concat the hash.
    digest = (H[0] << 32*7) \
           | (H[1] << 32*6) \
           | (H[2] << 32*5) \
           | (H[3] << 32*4) \
           | (H[4] << 32*3) \
           | (H[5] << 32*2) \
           | (H[6] << 32*1) \
           | (H[7])

    return digest
    
def my_sha256(msg: bytes) -> int:
    """Hash the message using SHA-256
    """
    msg_blocks = preprocess_msg(msg)
    digest = sha256_hash_computation(msg_blocks)
    return digest

def main():
    message = b'abc'
    print("PADDED:", pad_message(message));
    my_digest = my_sha256(message)

    print("MESSAGE:", message.hex())
    print("DIGEST: ", hex(my_digest)[2:])


if __name__ == '__main__':
    main()
