try:
    from socketserver import BaseRequestHandler
except ImportError:
    from SocketServer import BaseRequestHandler
import binascii as ba
from binascii import hexlify

from umodbus import log
from umodbus.functions import create_function_from_request_pdu
from umodbus.exceptions import ModbusError, ServerDeviceFailureError
from umodbus.utils import (get_function_code_from_request_pdu,
                           pack_exception_pdu, recv_exactly, recv_exactly_m)

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes
import socketserver
import socket
from Crypto.Cipher import AES
import string, base64
import random
import argparse
import os
from umodbus import conf
from umodbus.client import tcp
import hashlib as h
import ast
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
        verifier.verify(digest,b64decode(sig))
        return True
    except:
        return False

def getHash(msg):
    return str(h.sha256(msg).hexdigest())

def verifyHash(hashToVerify,hashGenerated):
    #print("verify hashToVerify: ",hashTsoVerify)
    #print("verify hashGenerated: ",hashGenerated)
    if hashToVerify in hashGenerated:
        return True
    else:
        print("Integrity Exception")
        raise Exception("Cannot Verify received message digest with the digest received")
        return False

def aes_cbc_encrypt(msg, obtained_key, iv,hashGenerated):
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
    #print('hkdf: {}' .format(ba.hexlify(obtained_key)))
    return obtained_key

def load_dh_params():
    with open('./dh_2048_params.bin', 'rb') as f:
        params = load_pem_parameters(f.read(), default_backend())
    #print('Parameters have been read from file, Server is ready for requests ...')
    return params

def generate_dh_prvkey(params):
    return params.generate_private_key()

def check_client_pubkey(pubkey):
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False


def route(self, slave_ids=None, function_codes=None, addresses=None):
    """ A decorator that is used to register an endpoint for a given
    rule::

        @server.route(slave_ids=[1], function_codes=[1, 2], addresses=list(range(100, 200)))  # NOQA
        def read_single_bit_values(slave_id, address):
            return random.choise([0, 1])

    :param slave_ids: A list or set with slave id's.
    :param function_codes: A list or set with function codes.
    :param addresses: A list or set with addresses.
    """
    def inner(f):
        self.route_map.add_rule(f, slave_ids, function_codes, addresses)
        return f

    return inner


class AbstractRequestHandler(BaseRequestHandler):
    """ A subclass of :class:`socketserver.BaseRequestHandler` dispatching
    incoming Modbus requests using the server's :attr:`route_map`.

    """



 
    def handle(self):
        try:
            helloMsgServer = 'server'
            helloMsgClient = 'client'

            serverkey = RSA.generate( 2048 )
            serverpbkey = serverkey.publickey().exportKey( 'PEM' ).decode( 'ascii' )
            serverprkey = serverkey.exportKey( 'PEM' ).decode( 'ascii' )
            print( '\nServer Public keys:\n\n', serverpbkey, '\n\n\nRSA server private key:\n\n', serverprkey )
            sign = signData( helloMsgServer.encode(), serverprkey )
            print( "\n\nSign:\n\n", sign )
            message = str( serverpbkey ) + ";" + str( sign )
            print( "\n\nRSA Message:\n\n", message )
            self.request.sendall( message.encode() )

            rsaResponse = self.request.recv(3072).strip()
            rsaMsg = rsaResponse.decode()
            clientpbkey = rsaMsg.split(';')[0]
            signRcvd = rsaMsg.split(';')[1]
            verify = verifySign(helloMsgClient.encode(),clientpbkey,signRcvd)
            if verify:
                print("\n\n---------Received Client RSA Public Key---------\n")
            else:
                raise Exception("\nClient Authentication Failure. RSA public key and sign don't match\n")
            print('\nRSA client pub key\n\n',clientpbkey)

            print("\n\n****************************RSA Exchange Completes and Authentication Done***************************")
            #self.state = 0
            
            dh_params = load_dh_params()
            srkey = generate_dh_prvkey(dh_params)

            response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(response)
            self.data = self.request.recv(3072).strip()
            print( "\n\n****************************Received Client's public Key****************************\n" )
            if bytearray(self.data)[0:18] == b'Client public key:':
                # now we convert the binary message to bytearray so we can choose the public key 
                # part of it and use key serialization method to turn it into an object
                client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
                # now if the public key is loaded (we might not get to this point otherwise, 
                # something for you to check!)
                if client_pubkey:
                    # client key is valid so we generate our own from the parameters
                    server_keypair = srkey

                    # we   will send the public key to the client and we need to convert it to 
                    # binary to send over the network
                    response = b'Server public key:' + server_keypair.public_key().public_bytes(
                        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

                    session_key = server_keypair.exchange(client_pubkey)
                    #self.state = 0
                    self.request.sendall(response)
                    print( "\n****************************Shared Secret key is generated***************************\n" )
                    print("\n**********************DH Exchange Completes and Session Established**********************" )
                else:
                    # if we get here the client key is not right
                    response = b'Invalid client public key, hanging up'
                    self.request.sendall(response)
                    return

            iv = 'nvXIK5RtUZpZQdJD'
            while True:
                try:
                      message=self.request.recv(1024)
                      if not message:
                          break
                      #print('\niv',iv)
                      self.iv = iv
                      print('\nCipher + Hash:\t\t-------->\t',(message))
                      obtained_key = hkdf_function(session_key)
                      self.obtained_key = obtained_key
                      plain,digest = aes_decrypt(message,obtained_key,iv)
                      print('\nDerived key:\t\t-------->\t',(obtained_key))
                      localDigest = getHash(plain)
                      verify = verifyHash(digest,localDigest)
                      if verify == False:
                          break
                      print("\nHash is verified.")
                      mbap_header = plain[0:7]
                      remaining = self.get_meta_data(mbap_header)['length'] - 1
                      request_pdu = plain[7:8+remaining]
                      
                except ValueError:
                    print("issue")
                    return
		 	
                response_adu = self.process(mbap_header + request_pdu)
                print("\nResponse ADU:\t\t-------->\t",(response_adu))
                #At this point the responce to the message  has been structured and is ready to be send to the client
                self.respond(response_adu)
        except:
            import traceback
            log.exception('Error while handling request: {0}.'
                          .format(traceback.print_exc()))
        raise

    def process(self, request_adu):
        """ Process request ADU and return response.

        :param request_adu: A bytearray containing the ADU request.
        :return: A bytearray containing the response of the ADU request.
        """
        meta_data = self.get_meta_data(request_adu)
        request_pdu = self.get_request_pdu(request_adu)

        response_pdu = self.execute_route(meta_data, request_pdu)
        response_adu = self.create_response_adu(meta_data, response_pdu)

        return response_adu

    def execute_route(self, meta_data, request_pdu):
        """ Execute configured route based on requests meta data and request
        PDU.

        :param meta_data: A dict with meta data. It must at least contain
            key 'unit_id'.
        :param request_pdu: A bytearray containing request PDU.
        :return: A bytearry containing reponse PDU.
        """
        try:
            function = create_function_from_request_pdu(request_pdu)
            results =\
                function.execute(meta_data['unit_id'], self.server.route_map)

            try:
                # ReadFunction's use results of callbacks to build response
                # PDU...
                return function.create_response_pdu(results)
            except TypeError:
                # ...other functions don't.
                return function.create_response_pdu()
        except ModbusError as e:
            function_code = get_function_code_from_request_pdu(request_pdu)
            return pack_exception_pdu(function_code, e.error_code)
        except Exception as e:
            log.exception('Could not handle request: {0}.'.format(e))
            function_code = get_function_code_from_request_pdu(request_pdu)

            return pack_exception_pdu(function_code,
                                      ServerDeviceFailureError.error_code)

    def respond(self, response_adu):
        """ Send response ADU back to client.

        :param response_adu: A bytearray containing the response of an ADU.
        """
        log.info('--> {0} - {1}.'.format(self.client_address[0],
                 hexlify(response_adu)))
        digest = getHash(response_adu)
        response_adu = aes_cbc_encrypt(response_adu,self.obtained_key,self.iv,digest)
        print('\nEncrypted Response ADU:\t-------->\t',response_adu,"\n\n")
        response_adu_bytes = response_adu.encode('utf-8')
        self.request.sendall(response_adu_bytes)
