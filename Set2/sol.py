import base64
from string import ascii_lowercase as alc
from binascii import hexlify
import math
from Crypto.Cipher import AES
import random


file = open("input.txt","r")
global_key = b''
unkownstring = base64.b64decode(file.read().encode())

def fixedLenXOR(byts1, byts2) -> bytes:
    return bytes(a^b for a, b in zip(byts1,byts2))

def PCKS7Padding(byts, length) -> bytes:
    return byts + int.to_bytes(length-len(byts))*(length-len(byts))

def encryptAESECB(plaintext,key) -> bytes:
    cipher = AES.new(key,mode=AES.MODE_ECB)
    encrypted = cipher.encrypt(plaintext)

    return encrypted

def encryptAESCBC128(plaintext,key,IV=b'\x00'*16) -> bytes:
    result = b''
    last_block = IV

    for i in range(math.ceil(len(plaintext)//16)):
        cur_plaintext = plaintext[16*i:16*(i+1)]
        xored_plaintext = fixedLenXOR(cur_plaintext,last_block)
        cur_ciphertext = encryptAESECB(xored_plaintext,key)
        result += cur_ciphertext
        last_block = cur_ciphertext
            
    return result

def decryptAESECB(ciphertext ,key) -> bytes:
    cipher_dec = AES.new(key,mode=AES.MODE_ECB)
    decrypted = cipher_dec.decrypt(ciphertext)

    return decrypted

def decryptAESCBC128(ciphered_msg, key, IV=b'\x00'*16):
    '''128 bytes AES, 16 bytes key'''
    result = b''

    last_block = IV#b'\x00'*16 
    for i in range(math.ceil(len(ciphered_msg)//16)):
        cur_ciphertext = ciphered_msg[16*i:16*(i+1)]
        xored_plaintext = decryptAESECB(cur_ciphertext,key)
        plaintext = fixedLenXOR(xored_plaintext,last_block)
        result += plaintext
        last_block = cur_ciphertext
    
    return result

def getRandByteString(expectedSize) -> bytes:
    key = b''
    for k in range(expectedSize):
        key += int.to_bytes(random.randint(0,255))
    return key

def genRandKey16() -> bytes:
    return getRandByteString(16)

#global_counter = True

def unknownKeyEncryption(plaintext) -> bytes:
    #global global_counter
    rand_len_padding = random.randint(5,10)
    plaintext = getRandByteString(rand_len_padding) + plaintext + getRandByteString(rand_len_padding)
    padded_pt = PCKS7Padding(plaintext, len(plaintext) + (16 - (len(plaintext) % 16))%16)
    key = genRandKey16()

    coin_flip = random.randint(0,1)
    result = b''
    if coin_flip == 0:
        #if global_counter:
        #    print("Ciphered using ECB")
        #ECB
        result = encryptAESECB(padded_pt,key)
    else:
        #CBC
        #if global_counter:
        #    print("Ciphered using CBC")
        rnd_iv = getRandByteString(16)
        result = encryptAESCBC128(padded_pt,key,rnd_iv)

    global_counter = False
    return result

def detectBlockCipher(ciphertext):
    seen_blocks = set(ciphertext[16*i:16*(i+1)] for i in range(math.ceil(len(ciphertext)/16)))

    if len(seen_blocks) < math.ceil(len(ciphertext)/16):
        return "ECB"
    else:
        return "CBC"


#AES-128-ECB(plaintext || unknown-string, random-key)
def constKeyECBEncryption(plaintext) -> bytes:
    global global_key, unkownstring
    plaintext += unkownstring
    padded_pt = PCKS7Padding(plaintext, len(plaintext) + (16 - (len(plaintext) % 16))%16)
    if len(global_key) == 0:
        global_key = genRandKey16()
    return encryptAESECB(padded_pt,key=global_key)

def ECBDecryptionSimple():
    plaintext = b'A'
    ciphertext = constKeyECBEncryption(plaintext)
    last_ciphertext = ciphertext
    counter = 0
    while len(ciphertext) == len(last_ciphertext):
        plaintext += b'A'
        last_ciphertext = ciphertext
        ciphertext = constKeyECBEncryption(plaintext)
        counter += 1

    blocksize = len(ciphertext)-len(last_ciphertext)
    ciphertext = constKeyECBEncryption(plaintext*32)

    target_len = (len(constKeyECBEncryption(b''))//16 - 1)*16 + (blocksize - counter) #unknownstring length

    if detectBlockCipher(ciphertext) != "ECB":
        return "ERROR - NOT ECB"
    
    decryptedMsg = b''
    prefix = b'A'*(blocksize-1)

    counter = 0
    while counter < target_len:
        block_idx = counter//16

        real_ECB = constKeyECBEncryption(prefix[:blocksize-1-(counter%blocksize)])[block_idx*blocksize:(block_idx+1)*blocksize]

        guessed_byte = b''
        for i in range(256):
            guessed_byte = int.to_bytes(i)
            guess_ECB = constKeyECBEncryption(prefix + guessed_byte)[0:blocksize]#[block_idx*blocksize:(block_idx+1)*blocksize]
            if real_ECB==guess_ECB:
                break
        decryptedMsg += guessed_byte
        prefix = prefix[1:] + guessed_byte

        counter+=1

    return decryptedMsg




if __name__ == "__main__":
    print(ECBDecryptionSimple())
    #plaintext = b"Yellow SubmarineTwo One Nine TwoYellow Submarine" * 2
    #print(detectBlockCipher(unknownKeyEncryption(plaintext)))

    #tmp = encryptAESCBC128(b"I'm back and I'm ringin' the bel",b'YELLOW SUBMARINE')
    #print(decryptAESCBC128(tmp,b'YELLOW SUBMARINE'))
    
    #file = open("input.txt","r")
    #print(decryptAESCBC128(base64.b64decode(file.read().encode()),b'YELLOW SUBMARINE'))
    #print(PCKS7Padding(b'YELLOW SUBMARINE',20))
    pass