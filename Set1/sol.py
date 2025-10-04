import base64
from string import ascii_lowercase as alc
from binascii import hexlify
import math
from Crypto.Cipher import AES

INF = 1e9

def hexToBytes(hex_in):
    result = bytes.fromhex(hex_in)
    return result

def bytesToB64(byts_in):
    return base64.b64encode(byts_in)

def fixedXOR(hex1, hex2): 
    '''XORs 2 hex strings'''
    return bytes(a^b for a, b in zip(hexToBytes(hex1),hexToBytes(hex2)))

def score(encoded_msg):
    LETTER_FREQUENCY = {
        # Letters (approx. proportion of total characters)
        'a': 0.065, 'b': 0.012, 'c': 0.022, 'd': 0.034, 'e': 0.102,
        'f': 0.018, 'g': 0.016, 'h': 0.049, 'i': 0.056, 'j': 0.001,
        'k': 0.006, 'l': 0.033, 'm': 0.020, 'n': 0.054, 'o': 0.060,
        'p': 0.015, 'q': 0.001, 'r': 0.048, 's': 0.050, 't': 0.073,
        'u': 0.022, 'v': 0.007, 'w': 0.019, 'x': 0.001, 'y': 0.016,
        'z': 0.001,

        # Punctuation (ballpark for modern prose)
        '.': 0.045,
        ',': 0.040,
        '?': 0.003,
        '!': 0.002,
        ':': 0.001,
        ';': 0.001,
        "'": 0.007,
        '"': 0.007,
        '-': 0.003,
        '(': 0.001,
        ')': 0.001,
        '\n' : 0,

        # Space (most common single character)
        ' ': 0.18,

        '0': 0,'1': 0,'2': 0,'3': 0,'4': 0,'5': 0,'6': 0,'7': 0,'8': 0,'9': 0
    }


    ACTUAL_LETTER_FREQUENCY = dict()
    for key in LETTER_FREQUENCY.keys():
        ACTUAL_LETTER_FREQUENCY[key]=0
    result = 0

    for i in range(len(encoded_msg)):
        ch = encoded_msg[i:i+1].decode('latin-1').lower()
        if not ch in LETTER_FREQUENCY.keys():
            return INF
        
        ACTUAL_LETTER_FREQUENCY[ch] += 1/len(encoded_msg)

    for ch in LETTER_FREQUENCY.keys():
        result += pow(2,abs(LETTER_FREQUENCY[ch]-ACTUAL_LETTER_FREQUENCY[ch]))

    return result


def SingleByteXORCipher(ciphered_msg): 
    '''returns secret byte'''
    min_score = INF
    min_key = 0
    for i in range(256):
        candidate_score = score(fixedXOR(ciphered_msg,bytes.hex(int.to_bytes(i)) * (len(ciphered_msg) // 2)))
        if  candidate_score < min_score:
            min_score = candidate_score
            min_key = i

    return fixedXOR(ciphered_msg,bytes.hex(int.to_bytes(min_key)) * (len(ciphered_msg) // 2)), int.to_bytes(min_key)#, min_score

def DetectSingleCharXOR(filename):
    file = open(filename,"r")
    result = ("","",INF)
    for line in file:
        candidate = SingleByteXORCipher(line.strip())
        if candidate[2] < result[2]:
            result = candidate
    return result

def RepeatingKeyXOR(plaintext, key):
    hexed_plaintext = hexlify(plaintext.encode())
    hexed_key = hexlify(key.encode())
    hexed_key *= math.ceil(len(hexed_plaintext)/len(hexed_key))
    return bytes.hex(fixedXOR(hexed_plaintext.decode(),hexed_key[:len(hexed_plaintext)].decode()))

def HammingDist(s1, s2):
    
    result = 0
    XORED = fixedXOR(str(hexlify(s1.encode()))[2:-1],str(hexlify(s2.encode()))[2:-1])
    for i in range(len(XORED)):
        result += bin(XORED[i:i+1][0]).count('1')

    return result

def hex_padded(num):
    result = hex(num)[2:]
    if len(result)%2==1:
        result = "0"+result
    return result

def BreakingRepKeyXOR(filename):
    file = open(filename,"r")
    #encrypted_msg = base64.b64decode(file.read().encode()).decode()
    encrypted_msg = base64.b64decode(file.read().strip().encode()).decode()

    ORDKEYSIZE = []
    for KEYSIZE in range(3,41):
        cur_editdist1 = HammingDist(encrypted_msg[:KEYSIZE],encrypted_msg[KEYSIZE:2*KEYSIZE])/KEYSIZE
        cur_editdist2 = HammingDist(encrypted_msg[2*KEYSIZE:3*KEYSIZE],encrypted_msg[3*KEYSIZE:4*KEYSIZE])/KEYSIZE
        cur_editdist = (cur_editdist1+cur_editdist2)/2
        
        ORDKEYSIZE.append((cur_editdist,KEYSIZE))
    
    ORDKEYSIZE.sort()

    result_keys = []

    for k in range(5):
        KEYSIZE = ORDKEYSIZE[k][1]
        blocks = [encrypted_msg[j*KEYSIZE:(j+1)*KEYSIZE] for j in range(len(encrypted_msg)//KEYSIZE)]

        chains = [[blocks[j][i] for j in range(len(blocks))] for i in range(KEYSIZE)]
        
        final_key = b''
        
        for i in range(KEYSIZE):
            hex_chain = ''.join(hex_padded(ord(chains[i][j])) for j in range(len(chains[i])))
            final_key += SingleByteXORCipher(hex_chain)[1]

        result_keys.append(final_key)

    with open('output.txt','w') as f:
        counter = 0
        for key in result_keys:
            result = RepeatingKeyXOR(str(encrypted_msg), str(key)[2:-1].replace("\\x",""))
            print(f"{counter}'th candidate is {bytes.fromhex(result)}",file=f)
            counter+=1


    return result_keys

def decryptAESinECB(filename,key):
    file = open(filename,"r")
    ciphertext = base64.b64decode(file.read().strip().encode())

    cipher_dec = AES.new(key,mode=AES.MODE_ECB)
    decrypted = cipher_dec.decrypt(ciphertext)

    return decrypted

def detectAESinECB(filename):
    '''Ideas - 
    we assume the plaintext is some reasonable text from the english language
    thus the ciphertext where the same 16 byte ciphertext will appear several times
    
    '''

    file_in = open(filename,"r")
    #file_out = open("output.txt","w")
    counter = 0
    suspect = -1
    for line in file_in:
        decoded_line = bytes.fromhex(line)
        seen = dict()
        for i in range(math.ceil(len(decoded_line)/16)):
            if decoded_line[16*i:16*(i+1)] not in seen.keys():
                seen[decoded_line[16*i:16*(i+1)]] = 0
            seen[decoded_line[16*i:16*(i+1)]] += 1
        
        if len(seen) < math.ceil(len(decoded_line)/16):
            suspect = counter
            #print(f"{counter}'th line is sus")
            #print(len(seen))
        counter+=1
    return suspect

if __name__ == "__main__":
    print(detectAESinECB("input.txt"))
    #decryptAESinECB("input.txt",b'YELLOW SUBMARINE')
    #candidate_keys = BreakingRepKeyXOR("input.txt")
    #print(HammingDist("this is a test","wokka wokka!!!"))
    
    #plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    #key = "ICE"
    #print(RepeatingKeyXOR(plaintext,key))
    #print(DetectSingleCharXOR("input.txt"))
    #print(SingleByteXORCipher("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    pass
