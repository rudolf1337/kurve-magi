
from Crypto.Util.number import long_to_bytes, bytes_to_long, isPrime
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import random
from Crypto.PublicKey import ECC, RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import os

"""
For hva er kryptografi egentlig verdt, i et deterministisk univers?
"""


def sha512(data):
    enveisfunksjon = SHA512.new()
    enveisfunksjon.update(data)
    return bytes_to_long(enveisfunksjon.digest())

# deterministisk frøet primtallsgenerator, gjør 128-bits frø til 1024-bits primtall
# husk: dem som har frøet, har primtallet
def finn_primtall(frø):
    s1 = sha512(long_to_bytes(frø))
    s2 = sha512(long_to_bytes(frø + 1337))
    primtall = s1 + (s2<<512)
    primtall = primtall | (1<<512)
    if not primtall%2:
        primtall += 1
    while not (isPrime(primtall)):
        primtall += 2
    return primtall

# s = p*q (mod 2^512), iff s = 1 (mod 2)
def finn_komplimentærprimtall(p, s):
    r = p % (1<<512)
    u = pow(r, -1, 1<<512)
    if not s%2: s |= 1
    primtall = ( s*u % (1<<512)) + (sha512(long_to_bytes(r))<<512)
    while not isPrime(primtall):
        primtall += sha512(long_to_bytes(primtall))<<512
        primtall %= 1<<1024
    return primtall

# det er her morroa skjer
def kurve_magi(klartekst, kurve_nøkkel):
    
    G = ECC.construct(curve='P-256', d=1).pointQ # workaround
    Q = kurve_nøkkel.pointQ
    eph = random.getrandbits(255) # midletidig nøkkel
    R = eph * Q
    S = eph * G # <--- R = d * S ;)
    hint = int(S.x)

    symmetrisk_nøkkel = long_to_bytes(int(R.x))
    symmetrisk_chiffer = AES.new(symmetrisk_nøkkel, AES.MODE_ECB)
    kryptert = symmetrisk_chiffer.encrypt(long_to_bytes(klartekst))

    return kryptert, hint

# her har du fire kryptografiske knep som sammen blir en kleptografisk bakdør
def hoved_funksjon():
    bakdør = random.getrandbits(255)
    kurve_nøkkel = ECC.construct(curve='P-256', d=bakdør)
    frø = random.getrandbits(128)

    kryptert, hint = kurve_magi(frø, kurve_nøkkel.public_key()) # for å gjøre kurve-magi, trenger vi kun en public key
    escrow = (bytes_to_long(kryptert)<<256) + hint

    p = finn_primtall(frø)
    q = finn_komplimentærprimtall(p, escrow)
    e = 0x10001
    n = p*q
    rsa_nøkkel = RSA.construct((n, e))
    aes_nøkkel = os.urandom(16)
    initialiseringsvektor = os.urandom(16)

    # alt det følgende, foruten bakdøren,
    # er per dags dato å regne som sikker kryptering
    if 'temmelig-hemmelig.txt' in os.listdir():
        # OBS! Klartekstmelding inneholder ASCII art.
        melding = open('temmelig-hemmelig.txt', 'rb').read()
        rsa_chiffer = PKCS1_OAEP.new(rsa_nøkkel)
        aes_chiffer = AES.new(aes_nøkkel, AES.MODE_CBC, iv=initialiseringsvektor)
        kryptert_sesjonsnøkkel = rsa_chiffer.encrypt(aes_nøkkel)
        chiffertekst = aes_chiffer.encrypt(melding + b'\n'*(16-(len(melding)%16)))
        
        print(rsa_nøkkel.export_key(format='PEM').decode())
        print(f'{kryptert_sesjonsnøkkel=}')
        print(f'{initialiseringsvektor=}')
        print(f'{chiffertekst=}')
        print(f"{bakdør=}")
    else:
        print("Feil: fila temmelig-hemmelig.txt må være tilstedet")
        return 1

if __name__ == '__main__':
    hoved_funksjon()
