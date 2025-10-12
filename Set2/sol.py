import base64
import math
from Crypto.Cipher import AES
import random
from urllib.parse import parse_qs
import string

file = open("input.txt","r")
global_key = b''
unkownstring = base64.b64decode(file.read().encode())

def fixedLenXOR(byts1, byts2) -> bytes:
    return bytes(a^b for a, b in zip(byts1,byts2))

def PCKS7Padding(byts, length) -> bytes:
    return byts + int.to_bytes(length-len(byts))*(length-len(byts))

def encryptAESECB(plaintext,key) -> bytes:
    if len(plaintext)%16 != 0:
        plaintext = PCKS7Padding(plaintext,((len(plaintext)-1)//16 + 1)*16)

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

def kvParsing(cookie):
    return {k : v[0] for k,v in parse_qs(cookie).items()}

def profile_for(username) -> str:
    translation_table = str.maketrans('','',string.punctuation)
    return username.translate(translation_table) + "&uid=10&role=user"

def encrypted_profile_for(username):
    global global_key
    if len(global_key) == 0:
        global_key = genRandKey16()
    
    return encryptAESECB(profile_for(username).encode(),global_key) 

def decrypt_profile_for_and_parse(ciphertext) -> str:
    global global_key
    return decryptAESECB(ciphertext,global_key).decode()


'''Challenge 13 - Idea
we'll replace the ECB block of user with ECB of admin
more precisely, we'll choose username of length s.t. "user" will be the first (and only) of its block
now, we would like to replace its block with one of "admin" as first and only. 
How would we do it? simply, we know such "admin" block is the encryption of "admin" padded with
int.to_bytes(11) 11 times. So, we'll take profile_for("admin and \x11 * 11") first block, replace
it with profile_for(pwn) last block. 
'''

def challenge13():
    poc = encrypted_profile_for("pwn")
    payload = encrypted_profile_for("admin" + "\0"*11)
    result = poc[:-16] + payload[:16]
    return result

#AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
def randomPaddingConstKeyECBEncryption(plaintext) -> bytes:
    global global_key, unkownstring
    plaintext += unkownstring
    padding_len = random.randint(0,100)
    if padding_len % 16 == 0:
        oof=0
    plaintext = getRandByteString(padding_len) + plaintext
    padded_pt = PCKS7Padding(plaintext, len(plaintext) + (16 - (len(plaintext) % 16))%16)
    if len(global_key) == 0:
        global_key = genRandKey16()
    return encryptAESECB(padded_pt,key=global_key)


def detectIndicatorIndex(ciphertext):
    cur_blocks = set()
    indicator_idx = -1
    for i in range(math.ceil(len(ciphertext)/16)):
        if ciphertext[16*i:16*(i+1)] in cur_blocks:
            indicator_idx = i
        else:
            cur_blocks.add(ciphertext[16*i:16*(i+1)])

    return indicator_idx


def challenge14():
    BRUTEFORCE_CONST = 160
    next_right = 0 #how many blocks to the right
    #payload = 'A'*16+'B'*16+
    payload = b'A'*64
    seen = set() #{AAA????,A??????,AAAAA??,...}
    decrypted_target = b''
    cur_window = b'A'*15

    while True:
        next_right += 1

        while len(seen) < 16:
            ciphertext = randomPaddingConstKeyECBEncryption(payload)
            indicator_idx = detectIndicatorIndex(ciphertext)

            if (indicator_idx+next_right)*16 >= len(ciphertext):
                return decrypted_target
            seen.add(ciphertext[(indicator_idx+next_right)*16:(indicator_idx+next_right+1)*16])
        
        for k in range(16):
            flag = False
            for i in range(128):
                if cur_window == b'A'*15 and i == 65:
                    continue

                guessed_byte = int.to_bytes(i)
                #if k==15 and i == 46:
                #    yikes=0

                for j in range(BRUTEFORCE_CONST):
                    guessed_ciphertext = randomPaddingConstKeyECBEncryption(payload+cur_window+guessed_byte)
                    indicator_idx = detectIndicatorIndex(guessed_ciphertext)
                    if k == 15:
                        indicator_idx -= 1

                    if guessed_ciphertext[16*(indicator_idx+1):16*(indicator_idx+2)] in seen:
                        seen.remove(guessed_ciphertext[16*(indicator_idx+1):16*(indicator_idx+2)])
                        flag = True
                        break

                if flag:
                    break

            if guessed_byte == b'\x7f':
                return decrypted_target
            
            decrypted_target += guessed_byte
            cur_window = cur_window[1:] + guessed_byte
            #print(decrypted_target)
            

'''Challenge 14 - Idea
we'll add to attacker-controlled 4 blocks which when ciphered we can identify it is them, i.e.
b'A'*16 4 times
now, we'll find the last block of b'A'*16 and consider the block next to it
we'll maintain set of these blocks, and wait until it's of size 16
we're pretty done - bruteforce b'A'*15 + guessed_byte until there is a match in the set, and so on

to move to next block, we consider the block next-next to it, and so on

'''

if __name__ == "__main__":
    #print(challenge14())
    #print(decrypt_profile_for_and_parse(challenge13()))
    #print(profile_for("pwn"))
    #print(kvParsing("foo=bar&baz=qux&zap=zazzle"))
    #print(ECBDecryptionSimple())
    #plaintext = b"Yellow SubmarineTwo One Nine TwoYellow Submarine" * 2
    #print(detectBlockCipher(unknownKeyEncryption(plaintext)))

    #tmp = encryptAESCBC128(b"I'm back and I'm ringin' the bel",b'YELLOW SUBMARINE')
    #print(decryptAESCBC128(tmp,b'YELLOW SUBMARINE'))
    
    #file = open("input.txt","r")
    #print(decryptAESCBC128(base64.b64decode(file.read().encode()),b'YELLOW SUBMARINE'))
    #print(PCKS7Padding(b'YELLOW SUBMARINE',20))
    pass
