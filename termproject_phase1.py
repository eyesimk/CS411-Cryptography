import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25308

def random_prime(bitsize):
    # random.seed(42)
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2 ** (bitsize - 1), 2 ** bitsize - 1)
        chck = sympy.isprime(p)
    warnings.simplefilter('default')
    return p


curve = Curve.get_curve('secp256k1')



# TODO: HERE CREATE A LONG TERM KEY

random.seed(42)
sL = randint(1, random_prime(256) - 1)
print("sL: ", sL)

# base point P is the generator
P = curve.generator

lkey = sL * P
print("lkey: ", lkey)


n = curve.order
print("n: ", n)

k = randint(1, n - 2)
print("k: ", k)

R = k * P
print("R: ", R)

r = (R.x) % n
print("r: ", r)

m = "25097"

h_ = SHA3_256.new(b'25097' + r.to_bytes((r.bit_length() + 7) // 8, byteorder='big'))

h = (int.from_bytes(h_.digest(), byteorder='big')) % n
print("h: ", h)

s = (sL * h + k) % n
print("s: ", s)

# print("sL: ", sL)
print("LKey.x: ", lkey.x)
print("LKey.y: ", lkey.y)
# print("LKey: ", lkey)


V = (s * P) - (h * lkey)
print("V: ", V)

v = V.x % n
print("v: ", v)

h_2 = SHA3_256.new(b'25097' + v.to_bytes((v.bit_length() + 7) // 8, byteorder='big'))

h_new = (int.from_bytes(h_2.digest(), byteorder='big')) % n

if h == h_new:
    print("true")

else:
    print("false")


n = curve.order

# HERE GENERATE A EPHEMERAL KEY

e_sL = randint(1, random_prime(256) - 1)
print("e_sL: ", e_sL)

# base point P is the generator
ekey = e_sL * P
print("e_Lkey: ", ekey)
print("e_Lkey.x: ", ekey.x)
print("e_Lkey.y: ", ekey.y)

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

try:

    
    # REGISTRATION
    mes = {'ID': stuID, 'h': h, 's': s, 'LKEY.X': lkey.x, 'LKEY.Y': lkey.y}
    response = requests.put('{}/{}'.format(API_URL, "RegStep1"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    print(response.json())

    print("Enter verification code which is sent to you: ")
    code = int(input())

    mes = {'ID': stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegStep3"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    print(response.json())

    
    
    # STS PROTOCOL

    mes = {'ID': stuID, 'EKEY.X': ekey.x, 'EKEY.Y': ekey.y}
    response = requests.put('{}/{}'.format(API_URL, "STSStep1&2"), json=mes)
    if ((response.ok) == False): raise Exception(response.json())
    res = response.json()
    
    #calculate T,K,U


    qB = Point(res['SKEY.X'], res['SKEY.Y'], curve)
    T = e_sL * qB
    print("x coordinate of T: ",T.x)
    print("y coordinate of T: ",T.y)

    a = "BeYourselfNoMatterWhatTheySay"
    U = str(T.x) + str(T.y) + a
    U = bytes(U, 'utf-8')
    print("U:",U)

    K = SHA3_256.new(U)
    print("K: ", K)
 

    W1 = str(ekey.x) + str(ekey.y) + str(qB.x) + str(qB.y)
    print("W1: ", W1)

    #Sign Message

    sig_k = randint(1, n - 2)

    new_R = sig_k * P

    new_r = new_R.x % n

    m = bytes(W1, 'utf-8')

    byte_r = new_r.to_bytes((new_r.bit_length() + 7) // 8, byteorder='big')
    
    h_3 = SHA3_256.new(m + byte_r)

    sig_h = (int.from_bytes(h_3.digest(), byteorder='big'))
    sig_h = sig_h % n

    sig_s = (sL * sig_h + sig_k) % n

    print("sig_s: ", sig_s)
    print("sig_h: ", sig_h)

    Y1 = 's' + str(sig_s) + 'h' + str(sig_h)
    Y1 = bytes(Y1, 'utf-8')
    print("plaintext: ", Y1)

    #Encryption

    crypto = AES.new(K.digest(), AES.MODE_CTR)
    Y1 = crypto.encrypt(Y1)
    nonce = crypto.nonce
    print("Y1: ", Y1)
    print("nonce: ", nonce)

    final_message = nonce + Y1
    print("nonce + y1", final_message)
    ctext = int.from_bytes(final_message, byteorder='big')
    print("ctext", ctext)



    
    ###Send encrypted-signed keys and retrive server's signed keys
    mes = {'ID': stuID, 'FINAL MESSAGE': ctext}
    response = requests.put('{}/{}'.format(API_URL, "STSStep4&5"), json=mes)
    if ((response.ok) == False):
        raise Exception(response.json())
    ctext = response.json()


    #Decrypt

    W2 = ctext.to_bytes((ctext.bit_length() + 7) // 8, byteorder='big')
    print("Received encrypted ciphertext: ", W2)
    
    crypto = AES.new(K.digest(), AES.MODE_CTR, nonce=W2[0:8])
    decrypted = crypto.decrypt(W2[8:])

    decoded = decrypted.decode('UTF-8')
    print("Decrypted text: ", decoded)

    message = str(qB.x) + str(qB.y) + str(ekey.x) + str(ekey.y)
    message = bytes(message, 'utf-8')
    print("The message is:", message)

    s_nw = decoded[1:decoded.index('h')]
    h_nw = decoded[decoded.index('h') + 1:]
    s_nw = int(s_nw)
    h_nw = int(h_nw)

    #verify

    V = (s * P) - (h * lkey)
    print("V: ", V)

    v = V.x % n
    print("v: ", v)

    h_2 = SHA3_256.new(b'25097' + v.to_bytes((v.bit_length() + 7) // 8, byteorder='big'))

    h_new = (int.from_bytes(h_2.digest(), byteorder='big')) % n

    if h == h_new:
        print("true")

    else:
        print("false")

    # get a message from server for
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "STSStep6"), json=mes)
    ctext = response.json()

    print(ctext)



    #Decrypt
    num = ctext.to_bytes((ctext.bit_length() + 7) // 8, byteorder='big')
    crypto = AES.new(K.digest(), AES.MODE_CTR, nonce=num[0:8])
    dtext = crypto.decrypt(num[8:])

    decoded_dtext = dtext.decode('UTF-8')
    print("Decrypted text: ", decoded_dtext)


    #Add 1 to random to create the new message and encrypt it
    
    random = decoded_dtext[decoded_dtext.index('.') + 2:]
    text = decoded_dtext[:decoded_dtext.index('.') + 1]
    #print("Text: ", text)
    #print("Random: ", rand)
    random = int(random) + 1

    text = text + " " + str(random)
    print(text)
    text = bytes(text, 'utf-8')

    crypto = AES.new(K.digest(), AES.MODE_CTR)
    ctext = crypto.nonce + crypto.encrypt(text)
    ct = int.from_bytes(ctext, byteorder='big')
    print("Plaintext: ", text)



    # send the message and get response of the server
    mes = {'ID': stuID, 'ctext': ct}
    response = requests.put('{}/{}'.format(API_URL, "STSStep7&8"), json=mes)
    ctext = response.json()
    print("Response: ", ctext)

    num = ctext.to_bytes((ctext.bit_length() + 7) // 8, byteorder='big')
    crypto = AES.new(K.digest(), AES.MODE_CTR, nonce=num[0:8])
    dtext = crypto.decrypt(num[8:])
    print("Decrypted text: ", dtext.decode('UTF-8'))
    decoded_dtext = dtext.decode('UTF-8')
    #print(decoded_dtext)


except Exception as e:
    print(e)

