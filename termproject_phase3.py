import math
import timeit
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import hashlib, hmac, binascii
import json

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25097
stuID_B = 25308

ephemeralDictionary = []

def decrypt_messages(message, k_enc, k_mac):
    message = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    HMAC_given = message[-32:]
    message = message[0:-32]

    crypto = AES.new(k_enc, AES.MODE_CTR, nonce=message[0:8])
    dtext = crypto.decrypt(message[8:])
    dtext = str(dtext.decode('utf-8'))

    # verify the HMAC code
    h_ = hmac.new(k_mac, message[8:], hashlib.sha256)
    h_ = h_.digest()
    if HMAC_given == h_:
        print("hmac verified")

        # send decrypted messages to server
        mes = {'ID_A': stuID, 'DECMSG': dtext}
        response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
        print(response.json())

def ephemeral_signature_generator(curve, qA_x, qA_y, sL):
    n = curve.order
    k = randint(1, n - 2)
    R = k * P
    r = R.x % n
    concatenated = str(qA_x) + str(qA_y)
    concatenated = bytes(concatenated, 'utf-8')
    r = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    h = SHA3_256.new(concatenated + r)
    h = (int.from_bytes(h.digest(), byteorder='big')) % n
    s = (sL * h + k) % n

    return (h, s)

def ephemeral_generator(curve, P, sL):
    sA = randint(1, random_prime(256) - 1)
    qA = sA * P
    h, s = ephemeral_signature_generator(curve, qA.x, qA.y, sL)

    return (sA, qA, h, s)

def register_ephemeral_keys(sL, stuID):
    for i in range(10):
        sA, qA, h, s = ephemeral_generator(curve, P, sL)
        ephemeralDictionary.append([sA, qA.x, qA.y])

        # send ephemeral key
        mes = {'ID': stuID, 'KEYID': i, 'QAI.X': qA.x, 'QAI.Y': qA.y, 'Si': s, 'Hi': h}
        response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
        print(response.json())

def delete_ephemeral_keys(stuID, sL):
    ###delete ephemeral keys
    h, s = SignGen(str(stuID).encode(), curve, sL)
    mes = {'ID': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)

def encrypt_message(message,k_enc, k_mac):

    # TODO: encrypt message with k_enc using AES_CTR
    message = message.encode()
    crypto = AES.new(k_enc, AES.MODE_CTR)
    ctext = crypto.encrypt(message)

    #TODO: compute HMAC-SHA256 of the ciphertext with k_mac
    mac = hmac.new(k_mac, ctext, hashlib.sha256)
    mac = mac.digest()

    #TODO: concatenate the nonce, ciphertext and MAC

    nonce = crypto.nonce
    msg = nonce + ctext + mac
    msg = int.from_bytes( msg, byteorder='big')

    return msg

def session_key_generation(sA_i, qBj_x, qBj_y):

    '''
    print("qbjx type: ", type(qBj_x))
    if(type(qBj_x) is int):
        qBj_x = hex(qBj_x)
        qBj_y = hex(qBj_y)
        print(qBj_x)
    print("qbjx type: ", type(qBj_x))

    '''


    qB_j = Point(qBj_x, qBj_y, curve)

    T = sA_i * qB_j
    U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
    U = bytes(U, 'utf-8')

    # Compute the session keys
    k_enc = SHA3_256.new(U)
    k_enc = k_enc.digest()
    k_mac = SHA3_256.new(k_enc)

    k_mac = k_mac.digest()

    return k_enc, k_mac

def SignGen(stuID, curve, sL):
    n = curve.order
    k = randint(1, n - 2)
    R = k * P
    r = R.x % n
    r = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    concat = stuID + r
    h = SHA3_256.new(concat)
    h = (int.from_bytes(h.digest(), byteorder='big')) % n
    s = (sL * h + k) % n

    return h, s

def register_long_term_key(stuID):
    ####Register Long Term Key
    curve = Curve.get_curve('secp256k1')
    P = curve.generator

    sL = randint(1, random_prime(256) - 1)
    qL = sL * P
    print("sL= ", sL)
    print("qL= ", qL)

    s, h = SignGen(str(stuID).encode(), curve, sL)
    mes = {'ID': stuID, 'H': h, 'S': s, 'LKEY.X': qL.x, 'LKEY.Y': qL.y}
    response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
    print(response.json())

    code = int(input())

    mes = {'ID': stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegLong"), json=mes)
    print(response.json())

def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2 ** (bitsize - 1), 2 ** bitsize - 1)
        chck = sympy.isprime(p)
    warnings.simplefilter('default')

    return p

def check_status(stuID, h, s):
    # Check Status
    mes = {'ID_A': stuID, 'H': h, 'S': s}
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print("Status ", response.json())

def send_ephemeral_keys(stuID, i, ekey, s, h):
    # Send Ephemeral keys
    mes = {'ID': stuID, 'KEYID': i, 'QAI.X': ekey.x, 'QAI.Y': ekey.y, 'Si': s, 'Hi': h}
    response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
    print(response.json())

def get_key_of_student_b(stuID, stuID_B, s, h):
    ### Get key of the Student B
    mes = {'ID_A': stuID, 'ID_B': stuID_B, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqKey"), json=mes)
    res = response.json()
    print(res)
    return res["i"],res["j"],res["QBJ.x"],res["QBJ.y"]

def send_message_to_student_b(stuID, stuID_B, i, j, msg):
    ### Send message to student B
    mes = {'ID_A': stuID, 'ID_B': stuID_B, 'I': i, 'J': j, 'MSG': msg}
    response = requests.put('{}/{}'.format(API_URL, "SendMsg"), json=mes)
    print(response.json())

def reset_ephemeral_keys(stuID, sL):
    #####Reset Ephemeral Keys
    s, h = SignGen(str(stuID).encode(), curve, sL)
    mes = {'ID': stuID, 'S': s, 'H': h}
    print(mes)
    response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)
    print(response.json())

def reset_long_term_key(stuID):
    #####Reset Long Term Key
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json=mes)
    print(response.json())
    code = int(input())

    mes = {'ID': stuID, 'CODE': code}
    response = requests.get('{}/{}'.format(API_URL, "RstLong"), json=mes)
    print(response.json())


# create a long term key

curve = Curve.get_curve('secp256k1')
P = curve.generator

# For 25097
sL_25097 = 57145230364634701078616884652580698479665404788326533747522401390664714493080
qL_25097 = Point(0xe3596cc24bcf472a0b35a5bf8edbcf38e781de9a5e535b40ebfeb806c88372a7,
          0xd661a94e71ee2cac7dc4d1e86d1eaf5fe4c6b3dcfb622759ba51b14ab7297445, curve)

# For 25308
sL_25308 =  31302793511321131525929034026743786457831813306037410581451692117714553989088
qL_25308 =  Point(0x8780fff824a951a6fe828659fd82297ff474e4cee25023c5adb9a5d88fbf3de8 , 0x955f78254912866d3add2b93e58d40c8b7ffecb0b08c99c379bea20b3983a895, curve)



def refreshe_ephemerals_process(stuID, sL):
    reset_ephemeral_keys(stuID, sL)
    register_ephemeral_keys(sL, stuID)
    h, s = SignGen(str(stuID).encode(), curve, sL)
    check_status(stuID, h, s)

h, s = SignGen(str(stuID).encode(), curve, sL_25097)

check_status(stuID, h, s)


refreshe_ephemerals_process(stuID, sL_25097)


# TODO: 4.1 SENDING MESSAGES

def send_messages_process(message, stuID, stuID_B, sL):
    h, s = SignGen(str(stuID_B).encode(), curve, sL)
    i, j, qBj_x, qBj_y = get_key_of_student_b(stuID, stuID_B, s, h)
    k_enc, k_mac = session_key_generation( ephemeralDictionary[int(i)][0], qBj_x, qBj_y)
    msg = encrypt_message(message, k_enc, k_mac)
    send_message_to_student_b(stuID, stuID_B, i, j, msg)

message = "erene mesaj"
send_messages_process(message, stuID, stuID_B, sL_25097)

# TODO: 4.2 STATUS CONTROL
'''
h, s = SignGen(str(stuID).encode(), curve, sL_25097)
check_status(stuID, h, s)

h, s = SignGen(str(stuID_B).encode(), curve, sL_25308)
check_status(stuID_B,h, s)
'''
def get_your_message(stuID, s, h):
    ## Get your message
    mes = {'ID_A': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg_PH3"), json=mes)
    print(response.json())
    res = response.json()
    if (response.ok):  ## Decrypt message
        if(str(res) != "You dont have any new messages" ):
            k_enc, k_mac = session_key_generation(ephemeralDictionary[res['KEYID']][0], res['QBJ.X'], res['QBJ.Y'])
            decrypt_messages(res['MSG'], k_enc, k_mac)


#h, s = SignGen(str(stuID_B).encode(), curve, sL_25308)
#get_your_message(stuID_B,s,h)

#TODO: 4.3 SENDING MESSAGES TO PSEUDO-CLIENT FOR GRADING

m1 = "The world is full of lonely people afraid to make the first move."
m2 = "I don’t like sand. It’s all coarse, and rough, and irritating. And it gets everywhere.” Anakin Skywalker"
m3 = "Hate is baggage. Life’s too short to be pissed off all the time. It’s just not worth it."
m4 = "Well, sir, it’s this rug I have, it really tied the room together."
m5 = "Love is like taking a dump, Butters. Sometimes it works itself out. But sometimes, you need to give it a nice hard slimy push.” Eric Theodore Cartman"


message = m1
send_messages_process(message, stuID, 18007, sL_25097)


message = m2
send_messages_process(message, stuID, 18007, sL_25097)


message = m3
send_messages_process(message, stuID, 18007, sL_25097)


message = m4
send_messages_process(message, stuID, 18007, sL_25097)


message = m5
send_messages_process(message, stuID, 18007, sL_25097)






