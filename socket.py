import binascii
import socket as syssock
import struct
import sys

import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

from inspect import currentframe, getframeinfo

#global sock352portTx
#global sock352portRx

global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys
global in_publicKeys
global local_box

# the encryption flag
global ENCRYPT

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

sock352HdrStructStr = '!BBBBHHLLQQLL'


def init(UDPportTx, UDPportRx):
    #global sock352portTx = local_port_for_sending
    #global sock352portRx = local_port_for_receiving

    # create the sockets to send and receive UDP packets on
    # if the ports are not equal, create two sockets, one for Tx and one for Rx
    global sock
    global local_seq_number
    global local_ack_number
    local_seq_number = 0
    local_ack_number = 0
    global local_port_for_receiving
    local_port_for_receiving = (syssock.gethostbyname(syssock.getfqdn()), int(UDPportRx))
    global local_port_for_sending
    local_port_for_sending = (syssock.gethostbyname(syssock.getfqdn()), int(UDPportTx))

    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    sock.bind(local_port_for_receiving)
    #ADDING second socket
    print >> sys.stderr, 'Binding to UDPportRx ... %s' % UDPportRx
    pass

# read the keyfile. The result should be a private key and a keychain of
# public keys
def readKeyChain(filename):
    global publicKeysHex
    global privateKeysHex
    global publicKeys
    global privateKeys

    if (filename):
        try:
            keyfile_fd = open(filename, "r")
            for line in keyfile_fd:
                words = line.split()
                # check if a comment
                # more than 2 words, and the first word does not have a
                # hash, we may have a valid host/key pair in the keychain
                if ((len(words) >= 4) and (words[0].find("#") == -1)):
                    host = words[1]
                    port = words[2]
                    keyInHex = words[3]
                    if (words[0] == "private"):
                        privateKeysHex[(host, port)] = keyInHex
                        privateKeys[(host, port)] = nacl.public.PrivateKey(keyInHex, nacl.encoding.HexEncoder)
                    elif (words[0] == "public"):
                        publicKeysHex[(host, port)] = keyInHex
                        publicKeys[(host, port)] = nacl.public.PublicKey(keyInHex, nacl.encoding.HexEncoder)
        except Exception, e:
            print ("error: opening keychain file: %s %s" % (filename, repr(e)))
    else:
        print ("error: No filename presented")

    return (publicKeys, privateKeys)


def __generate_encryption_keys(filename, UDPportTx, UDPportRx):
    # global UDPportTxGl
    # global UDPportRxGl

    print 'UDPportTx: %s\n' % UDPportTx
    print 'UDPportRx: %s\n' % UDPportRx

    print ("DBG: Generating keys file")

    local_privk = PrivateKey.generate()

    privateKeysHex = local_privk.encode(encoder=nacl.encoding.HexEncoder)

    # this is the local public key in binary
    local_pubk = local_privk.public_key

    # convert the binary key to a printable version in hexadecimal
    publicKeysHex = local_pubk.encode(encoder=nacl.encoding.HexEncoder)
    # generate the receiver's keychain file
    keychainFile = open(filename, "w")
    keychainFile.write('private\t*\t*\t%s\n' % privateKeysHex)
    print type(UDPportTx)
    keychainFile.write('public\t%s\t%s\t%s\n' % (syssock.gethostbyname(syssock.getfqdn()), UDPportTx, publicKeysHex))
    if (UDPportTx != UDPportRx):
        keychainFile.write(
            'public\t%s\t%s\t%s\n' % (syssock.gethostbyname(syssock.getfqdn()), UDPportRx, publicKeysHex))

    return


class socket:
    global seq_number
    seq_number = 0
    global ack_number
    ack_number = 0

    def __init__(self):
        print >> sys.stderr, '\nRUNNING instance init() ... '
        global connection_list
        connection_list = []
        global fragment_list
        fragment_list = Queue.Queue()
        return


    def bind(self, address):
        print >> sys.stderr, '\nRUNNING instance bind() ... '
        return

    def connect(self, *args):#assuming both sides know we are go encrpted

        # example code to parse an argument list
        global local_port_for_sending
        global in_publicKeys
        global ENCRYPT
        global local_box
        if (len(args) >= 1):
            (host, port) = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True

                # your code goes here
        print >> sys.stderr, '\nRUNNING instance connect() ... '
        global seq_number
        global ack_number
        seq_number = random.randint(0, 1844674407370955161)
        ack_number = 0

        local_seq_number = seq_number
        bytesreceived = 0
        print >> sys.stderr, 'Initial Seq Number: %s' % seq_number
        print >> sys.stderr, 'Initial Ack Number: %s' % ack_number

        # def __prepare_header(self, flags, seq_number, ack_number, payload_len):

        header = self.__prepare_header(0x01, seq_number, ack_number, 0)
        message = header
        if self.encrypt == True:
            header = self.__prepare_header(0x01, seq_number, ack_number, len(publicKeys))
            message = header + publicKeys
        SYN_acked = False
        while (SYN_acked == False):
            sock.sendto(message, (local_port_for_sending))
            print ("Message sent from connect(): %s %s %s %s  %s %s %s %s  %s %s %s %s "
                   % (struct.unpack('!BBBBHHLLQQLL', message[0:40])))
            print >> sys.stderr, 'Sending SYN from ... \n', local_port_for_sending
            print >> sys.stderr, 'Block waiting for SYN ACK at ... \n', local_port_for_receiving

            sock.setblocking(0)
            ready = select.select([sock], [], [], 0.2)
            if ready[0]:
                bytesreceived, addr = sock.recvfrom(4096)

            if bytesreceived == 0:
                continue

            msg_rec = struct.unpack('!BBBBHHLLQQLL', bytesreceived[0:40])
            print >> sys.stderr, 'SYN ACK from addr: ', addr
            print ("SYN ACK Message: %s %s %s %s  %s %s %s %s  %s %s %s %s \n"
                   % (msg_rec))
            is_syn_ack = False
            is_reset = False
            is_syn_ack = (msg_rec[1] == 0x5)
            is_reset = (msg_rec[1] == 0x8)

            seqMatch = False
            seqMatch = (msg_rec[9] == local_seq_number + 1)

            print ('is_syn: %s\nis_reset: %s\nseqMatch: %s\n' % (is_syn_ack, is_reset, seqMatch))
            if (is_syn_ack == True & seqMatch == True):
                SYN_acked = True
                seq_number = msg_rec[9]
                ack_number = msg_rec[8]
                if self.encrypt == True:
                    end_posi_of_key = msg_rec[11]+40
                    in_publicKeys = bytesreceived[40:end_posi_of_key]
                    local_box = Box(privateKeys, in_publicKeys)
                    
                # if is_reset == True:
                # something
        print >> sys.stderr, 'About to return from connect() ... '
        return

def listen(self, backlog):
        # listen is not used in this assignments
        pass

    def accept(self, *args):
        # example code to parse an argument list
        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
                # your code goes here

    def close(self):
        # your code goes here
        return

    def send(self, buffer):
        # your code goes here
        return

    def recv(self, nbytes):
        # your code goes here
        return





