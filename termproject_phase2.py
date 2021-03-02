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
import hmac
import hashlib

API_URL = 'http://cryptlygos.pythonanywhere.com'

stuID = 25097


def register_long_term_key():
    h, s = sign_id(curve, b'25097', sL)

    ####Register Long Term Key
    mes = {'ID': stuID, 'H': h, 'S': s, 'LKEY.X': qL.x, 'LKEY.Y': qL.y}
    response = requests.put('{}/{}'.format(API_URL, "RegLongRqst"), json=mes)
    print(response.json())
    code = input()

    mes = {'ID': stuID, 'CODE': code}
    response = requests.put('{}/{}'.format(API_URL, "RegLong"), json=mes)
    print(response.json())


def delete_long_term_key():
    ###########DELETE LONG TERM KEY
    # If you lost your long term key, you can reset it yourself with below code.

    # First you need to send a request to delete it.
    mes = {'ID': stuID}
    response = requests.get('{}/{}'.format(API_URL, "RstLongRqst"), json=mes)

    # Then server will send a verification code to your email.
    # Send this code to server using below code
    # mes = {'ID': stuID, 'CODE', code}
    # response = requests.get('{}/{}'.format(API_URL, "RstLong"), json = mes)

    # Now your long term key is deleted. You can register again.


def random_prime(bitsize):
    warnings.simplefilter('ignore')
    chck = False
    while chck == False:
        p = random.randrange(2 ** (bitsize - 1), 2 ** bitsize - 1)
        chck = sympy.isprime(p)
    warnings.simplefilter('default')

    return p


def ephemeral_generator(curve, P, sL):
    sA = randint(1, random_prime(256) - 1)
    qA = sA * P
    h, s = signature_generator(curve, qA.x, qA.y, sL)

    return (sA, qA, h, s)


def register_ephemeral_keys():
    for i in range(10):
        sA, qA, h, s = ephemeral_generator(curve, P, sL)
        ephemeralDictionary[i] = [sA, qA.x, qA.y]

        # send ephemeral key
        mes = {'ID': stuID, 'KEYID': i, 'QAI.X': qA.x, 'QAI.Y': qA.y, 'Si': s, 'Hi': h}
        response = requests.put('{}/{}'.format(API_URL, "SendKey"), json=mes)
        print(response.json())


def delete_ephemeral_keys():
    ###delete ephemeral keys
    h, s = sign_id(curve, b'25097', sL)
    mes = {'ID': stuID, 'S': s, 'H': h}
    response = requests.get('{}/{}'.format(API_URL, "RstEKey"), json=mes)


def signature_generator(curve, qA_x, qA_y, sL):
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


def sign_id(curve, stuID, sL):
    n = curve.order
    k = randint(1, n - 2)
    R = k * P
    r = R.x % n
    r = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    concat = stuID + r
    h = SHA3_256.new(concat)
    h = (int.from_bytes(h.digest(), byteorder='big')) % n
    s = (sL * h + k) % n

    return (h, s)


def receive_messages():
    h, s = sign_id(curve, b'25097', sL)
    for i in range(5):
        # Receiving Messages
        mes = {'ID_A': stuID, 'S': s, 'H': h}
        response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
        print(response.json())


def session_key_generation(curve, messageObject):
    keyID = messageObject["KEYID"]
    qB_x = messageObject["QBJ.X"]
    qB_y = messageObject["QBJ.Y"]

    # generate session keys (qBj and i is given) k_enc -> sai*qBj   k_mac -> SHA3(k_enc)
    qA_i = Point(qB_x, qB_y, curve)

    sB_j = ephemeralDictionary[int(keyID)][0]
    T = sB_j * qA_i
    U = str(T.x) + str(T.y) + "NoNeedToRunAndHide"
    U = bytes(U, 'utf-8')

    # Compute the session keys
    k_enc = SHA3_256.new(U)
    k_enc = k_enc.digest()
    k_mac = SHA3_256.new(k_enc)

    k_mac = k_mac.digest()

    return k_enc, k_mac


def decrypt_messages(k_enc, k_mac, messageObject):
    message = messageObject["MSG"]
    message = message.to_bytes((message.bit_length() + 7) // 8, byteorder='big')
    HMAC_given = message[-32:]
    message = message[0:-32]

    crypto = AES.new(k_enc, AES.MODE_CTR, nonce=message[0:8])
    dtext = crypto.decrypt(message[8:])
    dtext = str(dtext.decode('UTF-8'))


     
    # verify the HMAC code
    h_ = hmac.new(k_mac, message[8:], hashlib.sha256)
    h_ = h_.digest()
    if HMAC_given == h_:
        print("hmac verified")


        # send decrypted messages to server
        mes = {'ID_A': stuID, 'DECMSG': dtext}
        response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
        print(response.json())

    #return dtext

 



# create a long term key
curve = Curve.get_curve('secp256k1')
P = curve.generator

sL = 57145230364634701078616884652580698479665404788326533747522401390664714493080
qL = Point(0xe3596cc24bcf472a0b35a5bf8edbcf38e781de9a5e535b40ebfeb806c88372a7,
           0xd661a94e71ee2cac7dc4d1e86d1eaf5fe4c6b3dcfb622759ba51b14ab7297445, curve)

# server's long term key
QSer_long = Point(0xc1bc6c9063b6985fe4b93be9b8f9d9149c353ae83c34a434ac91c85f61ddd1e9,
                  0x931bd623cf52ee6009ed3f50f6b4f92c564431306d284be7e97af8e443e69a8c, curve)

# TODO: 3.1 Registration of ephemeral keys

# ephemeralGenerator(curve, P, sL)
# registerEphemeralKeys()

# [sA, qA.x, qA.y]
ephemeralDictionary = [[21028296913145133599558212684188618271637816814982993767754174384508410459674,
                        97162995617590421571596718841163251305396862324144218881304865817368525355471,
                        88244997461808706685151863015100547494704077797920875012633677677733816389503],
                       [15825864487094875785900092011238381374284129461280351095680894711455367378798,
                        100593253051873863299110159672424121654364938392510199780198098691640912273952,
                        61813828404295402145108939449308847537428369851112607720743483838908826521527],
                       [72991078417427233478129321895185837710545931073782752050330408797342417261168,
                        67644813229290221199790654536177656672263823978231494425767401502807752634622,
                        84357744104207506388811852195555852898145643018570151956328739771192997994883],
                       [24219569357647866692613063038462123511636153197793921122450848397008650589252,
                        53194657161151705401804996242341043077559272620475875549845933236487945934947,
                        35444072760091360511837438165772925102137045856710201121056424013839661811699],
                       [78361974731991404983465474504962876615320137213642618688282701663392178105889,
                        113693192146171282439554587768964058497326985735944806888612137751580669011156,
                        24106389566185279273302955909493486430794877289820030825023949307452081851577],
                       [13312889799321127793262392445845145576980938669746529954496692531297592065473,
                        20363503232942211204457206480837809763290835960027808169009156195879646517459,
                        59713770145656921222576391921676761189132291663153570723756363028131124550595],
                       [29691790695846508148496496932048377855299932086608463772075277367218347276275,
                        84546613375207421281791031907899098170041565805708081402720271657263035001735,
                        77289576997148907403263144302942093926244708607218177005953877952282152542417],
                       [30134826348412626091074279429709076287609100138260476442910899992313784821022,
                        29840505776376764980490183382773295458486553576899876485127120124697475073986,
                        50179067246521717694070561454310035970548060594851987073741250702307103200437],
                       [8338629517898574055378592793185947150640353081105441035507354318389186903964,
                        79353956395748380732224305395294562116782975688501060391345437731637797571883,
                        52562889136020566959802182787207155455316975551090511624111635557829129807015],
                       [38655164463165991265537425962974985891820865665411230324575614298287091012384,
                        3548757012401206937187741140287230304670549711625869338178693343694598072320,
                        82619261606654184096644429148411190118898235374476373194712979968913853947452]]

# TODO: 3.2 Receiving Messages

# receiveMessages()

receivedMessages = [{'IDB': 18007, 'KEYID': '0',
                     'MSG': 2346863218384013276357020226194930901677658543251666032330337056993353747539846211966658569896931770858963246721069960493892044388291479303655202144471482652231210530711866036598824086365573792748446,
                     'QBJ.X': 107931982386184192711282289846387515199137312089240217161869561868208513322653,
                     'QBJ.Y': 16230854402396304276653427894008096274098760099202780878556703305299079637895},
                    {'IDB': 18007, 'KEYID': '1',
                     'MSG': 1906679346194817279185011915516059542061926500584267323434892779465238237875202707600783139056079414234798662817153437799898448310096332541201075707015403219760051916078311250655561490541490683029290,
                     'QBJ.X': 13245380785238482442254520369948551225451589899861056659603476932341742522640,
                     'QBJ.Y': 52597015443547473374166176765739174519138992936575968775082872536763657707746},
                    {'IDB': 18007, 'KEYID': '2',
                     'MSG': 35840990628914794117028905196143945703561534638630073865444721176720818415920642194284258716647364095480445501004100007246338182396226867335645139583331677347092242412813917749360256609848596930273029,
                     'QBJ.X': 26467389392690375073484959473852432350369471908651971947448553451660649911432,
                     'QBJ.Y': 20422507997538615388083550187685426485104659932829618146639356215891968783765},
                    {'IDB': 18007, 'KEYID': '3',
                     'MSG': 40577834579313592413999431439306343159568822100331070434021574395380387708701180074531799902229004055462524737245476583432435601032183628756077123991386808924119893103221566085443512594042306255813217,
                     'QBJ.X': 24052270938181503103832449735275907317126920134919694757367307946463717176186,
                     'QBJ.Y': 74493485911969175633642089405681664480267098306668021468691191214890239055280},
                    {'IDB': 18007, 'KEYID': '4',
                     'MSG': 28088166983148261989185811560116533815237751080909303468156977314014547239081274396244633207809222091691615331521233628286846655877224429515357873050554308442708122223426047447792811523502720472628046,
                     'QBJ.X': 9839383646405302752310210171236686618044296314911738637989359404616305266959,
                     'QBJ.Y': 106876525290870895517993794223375584480842863335862560164277740962892094010346}
                    ]

# TODO: 3.2.1 Session Key and msg Generation

for i in range(5):
    k_enc, k_mac = session_key_generation(curve, receivedMessages[i])
    dtext= decrypt_messages(k_enc, k_mac, receivedMessages[i])

# TODO: 3.2.2 Decrypting the messages
    
 
