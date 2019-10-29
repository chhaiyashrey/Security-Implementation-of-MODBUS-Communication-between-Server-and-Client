#!/usr/bin/env python
# scripts/examples/simple_tcp_client.py
import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import socketserver
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from umodbus import conf
from umodbus.client import tcp
import binascii as ba
import hashlib as h
import json
from base64 import b64decode
from base64 import b64encode
from hashlib import sha256
import hmac
import string
import random
from base64 import (
    b64encode,
    b64decode,
)

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

digest = SHA256.new()

def signData(msg, private_key):
    digest.update(msg)
    private_key = RSA.importKey(private_key)
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(digest)
    return b64encode(sig)

def verifySign(msg, publicKey, sig):
    publicKey = RSA.importKey(publicKey)
    digest.update(msg)
    verifier = PKCS1_v1_5.new(publicKey)
    try:
        verifier.verify(digest, b64decode(sig))
        return True
    except:
        return False
    
def getHash(msg):
    return str(h.sha256(msg).hexdigest())

def verifyHash(hashToVerify,hashGenerated):
   # print("verify hashToVerify: ",hashToVerify)
   # print("verify hashGenerated: ",hashGenerated)
    if hashToVerify in hashGenerated:
        return True
    else:
        print("Integrity Exception")
        return False
        raise ValidateError("Cannot Verify received message digest with the digest received")     

def aes_cbc_encrypt(msg, obtained_key, iv,hashGenerated):
    #print("plain text before digest: ",message)
    leng = 16 - (len(msg) % 16)
    msg += bytes([leng])*leng
    aes = AES.new(obtained_key, AES.MODE_CBC, iv)
    enc = aes.encrypt(msg)
    return (enc.hex()+";"+hashGenerated)


def aes_decrypt(enc, obtained_key, iv):
    enc = enc.decode('utf-8')
    enc1 = enc.split(";")
    enc = enc1[0]
    digest = enc1[1]
    enc = bytes.fromhex(enc)
    dec = AES.new(obtained_key, AES.MODE_CBC, iv)
    plain_text = dec.decrypt(enc)
    plain_text = plain_text[:-plain_text[-1]]
    return (plain_text,digest)


def hkdf_function(session_key):
    salt = b'alienware'
    info = b'hello world'
    backend = default_backend()
    hkdf = HKDF(algorithm=hashes.SHA256(),length=32, salt=salt, info=info, backend=backend)
    obtained_key=hkdf.derive(session_key)
    return obtained_key


def main():
    host, port = '10.8.8.20', 502
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
   
    iv = 'nvXIK5RtUZpZQdJD'
    helloMsgClient = 'client'
    helloMsgServer = 'server'
    clientkey = RSA.generate(2048)
    clientpukey = clientkey.publickey().exportKey('PEM').decode('ascii')
    clientprkey = clientkey.exportKey('PEM').decode('ascii')
    print('\nClient Public Key:\n\n',clientpukey,'\n\n\nClient Private Key:\n\n',clientprkey)
    sign = signData(helloMsgClient.encode(),clientprkey)
    print("\n\nSign:\n\n", sign)
    message = str(clientpukey)+";"+ str(sign)
    print("\n\nRSA Message:\n\n",message)
    sock.sendall(message.encode())
    
    rsaResponse = sock.recv(3072).strip()
    rsaMsg= rsaResponse.decode()
    serverpukey = rsaMsg.split(';')[0]
    signRcvd = rsaMsg.split(';')[1]
    verify = verifySign(helloMsgServer.encode(),serverpukey,signRcvd)
    if verify:
        print("\n\n---------Received Server RSA Public Key---------\n")
    else:
        raise Exception("\nClient Authentication Failure. RSA public key and sign don't match")
    print('\nRSA Server Public Key:\n\n',serverpukey)
    
    print("\n\n****************************RSA Exchange Completes and Authentication Done***************************")
    received = sock.recv(3072).strip()
    #print('\nDH key Received:\n{}'.format(received))
    dh_params = load_pem_parameters(received, default_backend())


    if isinstance(dh_params, dh.DHParameters):
        client_keypair = dh_params.generate_private_key()
        request = b'Client public key:' + client_keypair.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        sock.sendall(request)
        #print('\nreq',request)
    else:
        print('Bad response')
        sock.close()
        return

    # this means we are still in the game
    received = sock.recv(3072).strip()
    #print('Received:\n{}'.format(received))
    print("\n\n****************************Received Server's public Key****************************\n")
    # check the format of the message (or rather the beginning)
    if bytearray(received)[0:18] == b'Server public key:':
        # get the server's public key from the binary and its proper index to the end
        server_pubkey = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
        if isinstance(server_pubkey, dh.DHPublicKey):
            # calculate the shared secret
            session_key = client_keypair.exchange(server_pubkey)
            # print the shared secret
            #print('Shared Secret\n{}'.format(ba.hexlify(session_key)))
            print("\n****************************Shared Secret key is generated***************************\n")
            print("\n**********************DH Exchange Completes and Session Established**********************")
    
    conf.SIGNED_VALUES = True
    obtained_key = hkdf_function(session_key)
    print('\n\nDerived Key:\t\t-------->\t',(obtained_key))
    message = tcp.write_multiple_coils(slave_id=1, starting_address=1, values=[0, 0,1,1,1])
    digest = getHash(message)
    #print("\n\ndigest_str: ",digest)
    cipher = aes_cbc_encrypt(message, obtained_key, iv,digest)
    print('\nMessage:\t\t-------->\t',(message),type(message))
    print('\nCipher:\t\t\t-------->\t',(cipher),type(cipher))
    #print('derived-------->',obtained_key)
    sock.sendall(cipher.encode('utf-8'))
    
    mb_responce=sock.recv(1024)
    mb_responce,digest = aes_decrypt(mb_responce,obtained_key,iv)
    localDigest = getHash(mb_responce)
    verify = verifyHash(digest,localDigest)
    if verify == True:
        print( "\nResponse:\t\t-------->\t", (mb_responce) )
        responce = tcp.parse_response_adu( mb_responce, message )
        print( '\nParsed Response:\t-------->\t', (responce) )

        message = tcp.read_coils( slave_id=1, starting_address=1, quantity=5 )
        print( '\n\n\nSecond Message:\t\t-------->\t', (message) )
        print( '\nMessage(Hexa format):\t-------->\t', (ba.b2a_hex( message )) )
        digest = getHash( message )
        cipher = aes_cbc_encrypt( message, obtained_key, iv, digest )
        print( '\nCipher:\t\t\t-------->\t', (cipher) )

        sock.sendall( cipher.encode( 'utf-8' ) )
        mb_responce = sock.recv( 1024 )
        mb_responce, digest = aes_decrypt( mb_responce, obtained_key, iv )
        localDigest = getHash( mb_responce )
        verify = verifyHash( digest, localDigest )
        if verify == True:
            print( "\nResponse:\t\t-------->\t", (mb_responce) )
            responce = tcp.parse_response_adu( mb_responce, message )
            print( '\nParsed Response:\t-------->\t', (responce) )
    
    #iv11 = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for x in range(16))
    #print('iv11',iv11)

 
    sock.close()
if __name__ == '__main__':
    main()
