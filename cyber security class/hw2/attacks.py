"""
attacks.py

Homework 2 student starter file.

Implement the five functions below. You may add helper functions, but do not
change any required function name or signature.

Submit this file together with answers.pdf. Do not modify or submit the other
starter-package files.
"""

from __future__ import annotations

CTR_COUNTER_SIZE = 16
AES_BLOCK_SIZE = 16


def change_amount(ciphertext: bytes) -> bytes:
    """
    Task 1: CTR bit-flipping attack.

    The ciphertext encrypts exactly:
        b"from=alice&to=bob&amount=1000"

    Ciphertext format:
        16-byte ctr || CTR ciphertext

    Return a modified ciphertext that decrypts to:
        b"from=alice&to=bob&amount=9000"
 """
    copy = bytearray(ciphertext)
    position = CTR_COUNTER_SIZE+ 25
    copy[position] ^= 0x08
    return bytes(copy)


def recover_ctr_byte(ciphertext: bytes, position: int, oracle) -> int:
    """
    Task 3: Recover one message byte using only the null-byte format oracle.

    Args:
        ciphertext: 16-byte ctr || CTR ciphertext.
        position: zero-based byte position in the message.
        oracle: callable oracle(modified_ciphertext) -> bool.

    Returns:
        The recovered message byte as an int in [0, 255].

    Assumption:
        The original message contains no 0x00 bytes.

    Query limit:
        At most 255 oracle queries.
    """
    byte_index = CTR_COUNTER_SIZE + position

    for x in range(1, 256): #in range
            copy = bytearray(ciphertext)
            copy[byte_index] ^= x #xor 

            if oracle(bytes(copy)):
                return x

    raise ValueError("cant find the plaintext byte")


def recover_ctr(ciphertext: bytes, oracle) -> bytes:
    """
    Task 5: Recover the complete null-free message encrypted under CTR mode.

    The attack must work for arbitrary binary messages; do not assume that the
    message is ASCII or printable.

    Query limit:
        At most 255 * message_length oracle queries.
    """
    message_length = len(ciphertext) - CTR_COUNTER_SIZE

    recovered = bytearray()

    for position in range(message_length):
        byte =recover_ctr_byte(ciphertext, position,oracle)
        recovered.append(byte )

    return bytes(recovered)


def recover_cbc_block(previous_block: bytes, block: bytes, oracle) -> bytes:
  
    """
    Task 9: Recover one 16-byte CBC message block using the padding oracle.
    Args:
        previous_block: the 16-byte block immediately preceding block (or IV).
        block: the 16-byte ciphertext block whose message block is recovered.
        oracle: callable oracle(modified_ciphertext) -> bool.
    Returns:
        f_k^{-1}(block) XOR previous_block.
    The oracle accepts a complete CBC ciphertext and returns True iff the
    resulting decrypted message has valid PKCS#7 padding.
    Your implementation must handle cases in which more than one modification
    appears to produce valid padding.
    """
def recover_cbc_block(previous_block: bytes, block: bytes, oracle) -> bytes:
    intermediate = bytearray(16)
    plaintext = bytearray(16)

    #start from the last byte and work backwards
    for i in range(15, -1, -1):
        pad = 16- i
        modified = bytearray(previous_block)
        for j in range(i + 1, 16):
            modified[j] =intermediate[j] ^ pad
        #try byte value
        for guess in range(256):
            modified[i] = guess 
            if not oracle(bytes(modified) +block):
                continue 
            if pad == 1:
                check = bytearray(modified)
                check[i - 1] ^= 1
                if not oracle(bytes(check) +block):
                    continue
            intermediate[i] = guess^ pad
            plaintext[i] = intermediate[i] ^ previous_block[i]
            break
        else:
             raise ValueError("Could not recover CBC")
    return bytes(plaintext)

def recover_cbc(ciphertext: bytes, oracle) -> bytes:
    """
    Task 10: Recover the complete unpadded CBC message.

    Ciphertext format:
        IV || C1 || C2 || ... || Cn

    Recover every message block, concatenate the blocks, remove PKCS#7 padding,
    and return the original unpadded message.
    """
    blocks = []
    #split ciphertext into 16 
    for i in range(0, len(ciphertext), 16):
        blocks.append(ciphertext[i:i + 16])

    plaintext = bytearray()

    # recover each block using task 9
    for i in range(1, len(blocks)):
        previous_block = blocks[i - 1]
        block = blocks[i]
        recovered = recover_cbc_block(previous_block, block, oracle)
        plaintext.extend(recovered)
    pad = plaintext[ -1] #remove padding

    if pad <1 or pad > 16:
        raise ValueError("Invalid padding")
    
    if plaintext[-pad:] != bytes([pad ]) * pad:
        raise ValueError("Invalid padding")
    
    return bytes(plaintext[:-pad])
