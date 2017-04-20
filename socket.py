import binascii
import socket as syssock
import struct
import sys
import os.path
import select
import Queue
import random
import nacl.utils
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, Box

# if you want to debug and print the current stack frame
from inspect import currentframe, getframeinfo

# these are globals to the sock352 class and
# define the UDP ports all messages are sent
# and received from

# the ports to use for the sock352 messages
global sock352portTx
global sock352portRx

global UDPportTxGl
global UDPportRxGl

# the public and private keychains in hex format
global publicKeysHex
global privateKeysHex

# the public and private keychains in binary format
global publicKeys
global privateKeys

# the encryption flag
global ENCRYPT
global client_box
global server_box

publicKeysHex = {}
privateKeysHex = {}
publicKeys = {}
privateKeys = {}

# this is 0xEC
ENCRYPT = 236

# this is the structure of the sock352 packet
sock352HdrStructStr = '!BBBBHHLLQQLL'

# location of the keychain file
keychainFileName = 'keychain'
keychainFileNameSender = 'keychain-send'
keychainFileNameReceiver = 'keychain-rec'


# Init Rx and Tx ports
# UDPportTxGl = 0
# UDPportRxGl = 0


def init(UDPportTx, UDPportRx):
    global sock
    global sock352portTx
    global sock352portRx
    # global UDPportTxGl
    # global UDPportRxGl
    print 'UDPportTx: %s\n' % (UDPportTx)
    print 'UDPportRx: %s\n' % (UDPportRx)
    UDPportTxGl = UDPportTx
    UDPportRxGl = UDPportRx
    print 'UDPportTxGl: %s\n' % UDPportTxGl
    print 'UDPportRxGl: %s\n' % UDPportRxGl

    # create the sockets to send and receive UDP packets on
    # if the ports are not equal, create two sockets, one for Tx and one for Rx
    sock352portRxGl = (syssock.gethostbyname(syssock.getfqdn()), int(UDPportRxGl))
    if (UDPportTxGl != UDPportRxGl):
        sock352portTx = (syssock.gethostbyname(syssock.getfqdn()), int(UDPportTxGl))
    else:
        sock352portTx = (syssock.gethostbyname(syssock.getfqdn()), int(UDPportRxGl))


    __generate_encryption_keys(keychainFileName, sock352portTx)

    sock = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    sock.bind(sock352portRxGl)


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
        print ("error: No filename presented - generating keys file")

    return (publicKeys, privateKeys)



def readKeyChainRowLocalPublicKey():  # local_public_key
    host = sock352portTx[0]
    port = sock352portTx[1]
    key = publicKeys[('localhost', port)]
    print key

    pass

def __generate_encryption_keys(filename, sock352portTx):
    has_port = False

    try:
        file = open(filename, 'r')
        print 'flag0'
        if os.stat(filename).st_size == 0:
            local_privk = PrivateKey.generate()
            privateKeysHex = local_privk.encode(encoder=nacl.encoding.HexEncoder)
            local_pubk = local_privk.public_key
            publicKeysHex = local_pubk.encode(encoder=nacl.encoding.HexEncoder)
            keychainFile = open(filename, "w")
            print sock352portTx[0], sock352portTx[1]
            host = sock352portTx[0]
            port = sock352portTx[1]
            keychainFile.write('private\t*\t*\t%s\n' %privateKeysHex)
            keychainFile.write('public\t%s\t' %host)
            keychainFile.write('%s\t' %port)
            keychainFile.write('%s\n' %publicKeysHex)

            file.close()


        else:
            for line in file:
                words = line.split()
                print 'flag1'
                if ((len(words) == 4) and (words[0].find("#") == -1) and words[0] == "private"):
                    priv = words[3]

                if ((len(words) == 4) and (words[0].find("#") == -1) and has_port == False and words[0] != "private"):
                    print 'flag2'
                    print sock352portTx[0],sock352portTx[1]
                    print words[1],words[2]
                    if (sock352portTx[0] == words[1] and sock352portTx[1] == words[2]):
                        print 'flag3'
                        has_port = True

            if has_port == False:
                print 'flag4'
                print priv
                print 'flag5'

                try:
                    decoded_private_key = nacl.public.PrivateKey(priv, encoder=nacl.encoding.HexEncoder)
                    print 'flag6'

                except TypeError:
                    print "Error decoding the key"
                print decoded_private_key
                print 'flag7'

                sk = decoded_private_key
                print 'flag8'

                pk = sk.public_key
                print 'flag9'

                pkHex = pk.encode(encoder=nacl.encoding.HexEncoder)
                file = open(filename, 'a')

                file.write('public\t%s\t' %sock352portTx[0])
                file.write('%s\t' % sock352portTx[1])
                file.write('%s\n' % pkHex)

                file.close()
    except Exception, e:
        print ("error")
    pass

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
        # bind is not used in this assignment
        return

    def connect(self, *args):
        # example code to parse an argument list
        global sock352portTx
        global ENCRYPT
        global client_box
        if (len(args) >= 1):
            (host, port) = args[0]
        if (len(args) >= 2):
            if (args[1] == ENCRYPT):
                self.encrypt = True

                # your code goes here
                # call __sock352_get_packet to get a packet

            print >> sys.stderr, '\nRUNNING instance connect() ... '
        global seq_number
        global ack_number
        seq_number = random.randint(0, 1844674407370955161)
        ack_number = 0

        local_seq_number = seq_number
        bytesreceived = 0
        print >> sys.stderr, 'Initial Seq Number: %s' % seq_number
        print >> sys.stderr, 'Initial Ack Number: %s' % ack_number

        host = sock352portTx[0]
        port = sock352portTx[1]
        print host, port
        print publicKeysHex[('%s' % host,'%s' % port)]
        print privateKeysHex[('*','*')]
        # need a method to find the local public key to use here
        local_public_key_Hex = publicKeysHex[('%s' % host,'%s' % port)]
        # need a method to find the local private key
        local_private_key_Hex = privateKeysHex[('*','*')]

        try:
            local_public_key = nacl.public.PublicKey(local_private_key_Hex, encoder=nacl.encoding.HexEncoder)
        except TypeError:
            print "Error decoding the key"

        try:
            local_private_key = nacl.public.PrivateKey(local_private_key_Hex, encoder=nacl.encoding.HexEncoder)

        except TypeError:
            print "Error decoding the key"
        header = self.__prepare_header(0x01, seq_number, ack_number, len(local_public_key_Hex))
        message = header + local_public_key_Hex

        SYN_acked = False
        while (SYN_acked == False):
            sock.sendto(message, (sock352portTx))
            print ("Message sent from connect(): %s %s %s %s  %s %s %s %s  %s %s %s %s "
                   % (struct.unpack('!BBBBHHLLQQLL', header)))
            print >> sys.stderr, 'Sending SYN from ... \n', sock352portTx

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
                # here to define box

                SYN_acked = True
                seq_number = msg_rec[9]
                ack_number = msg_rec[8]
                len_of_key = 40 + msg_rec[11]
                incoming_public_key = bytesreceived[40:len_of_key]
                client_box = Box(local_private_key, incoming_public_key)


                # if is_reset == True:
                # something
        print >> sys.stderr, 'About to return from connect() ... '
        return

    def listen(self, backlog):
        # listen is not used in this assignments
        pass

    def accept(self, *args):
        # example code to parse an argument list
        print >> sys.stderr, '\nRUNNING instance accept() ... '

        global ENCRYPT
        if (len(args) >= 1):
            if (args[0] == ENCRYPT):
                self.encryption = True
        # your code goes here

        addr = self.__sock352_get_packet()
        print connection_list
        local_connection_list = connection_list
        print "socket, before s2=: ", socket()

        global s2
        s2 = socket()

        print "socket, after s2=: ", socket()
        print "s2: ", s2
        global connection_list
        connection_list = local_connection_list
        print connection_list, local_connection_list

        return (s2, addr)

    def close(self):
        # your code goes here
        return

    def send(self, buffer):
        # your code goes here
        print >> sys.stderr, '\nRUNNING instance send() ... '
        bytessent = 0  # fill in your code here
        bytesreceived = 0

        print seq_number
        print ack_number
        global seq_number
        global ack_number
        ack_number = ack_number + 1

        header = self.__prepare_header(0x04, seq_number, ack_number, (len(buffer)))
        message = header + buffer
        nonce = nacl.utils.random(Box.NONCE_SIZE)
        encrypted = client_box.encrypt(message, nonce)
        ACK_receipt = False
        while (not ACK_receipt):
            sock.sendto(encrypted, (sock352portTx))

            sock.setblocking(0)
            ready = select.select([sock], [], [], 0.2)
            if ready[0]:
                bytesreceived, addr = sock.recvfrom(4096)

            if bytesreceived == 0:
                continue

            msg_rec = struct.unpack('!BBBBHHLLQQLL', bytesreceived[0:40])
            print >> sys.stderr, 'ACK from addr: ', addr
            print ("SYN ACK Message: %s %s %s %s  %s %s %s %s  %s %s %s %s \n"
                   % (msg_rec))
            is_ack = False
            is_ack = (msg_rec[1] == 0x4)

            seqMatch = False
            seqMatch = ((msg_rec[9] == seq_number + 1) & (msg_rec[8] == ack_number))

            print ('is_ack: %s\nseqMatch: %s\n' % (is_ack, seqMatch))
            if (is_ack == True & seqMatch == True):
                ACK_receipt = True
                seq_number = msg_rec[9]
                ack_number = msg_rec[8]

        print 'len_bytesreceived: %d' % len(buffer)
        return len(buffer)

    def recv(self, nbytes):
        # your code goes here
        global recv_size
        recv_size = nbytes
        global fragment_list
        print >> sys.stderr, '\nRUNNING instance recv() ... '
        if fragment_list.empty() == False:
            print "test0"
            temp = fragment_list.get_nowait()
            if len(temp) > nbytes:
                need_bytes = temp[0:nbytes]
                temp = temp[nbytes:len(temp)]
                fragment_list.put(temp)
                return need_bytes
            else:
                return temp
        else:
            print "test1"
            addr = self.__sock352_get_packet()
            temp = fragment_list.get_nowait()
            need_bytes = temp[0:nbytes]
            temp = temp[nbytes:len(temp)]
            fragment_list.put(temp)
            return need_bytes
        return

    def __generate_keychainFile(self):

        return

    def __sock352_get_packet(self):
        print >> sys.stderr, '\tRUNNING instance __sock352_get_packet() ... '
        isConnect = False
        is_syn = False
        is_ack = False
        is_fin = False
        send_reset = False
        accept_call = False
        recv_call = False
        fin_call = False
        while (isConnect == False):
            sock.setblocking(0)
            ready = select.select([sock], [], [], 0.2)
            if ready[0]:
                bytesreceived, addr = sock.recvfrom(64000)
                print len(bytesreceived)

            msg_rec = struct.unpack('!BBBBHHLLQQLL', bytesreceived[0:40])
            if msg_rec[1] == 0x01:
                is_syn = True
            if msg_rec[1] == 0x04:
                is_ack = True
            if msg_rec[1] == 0x02:
                is_fin = True

            if ((is_syn == True) & (len(connection_list) == 0)):
                isConnect = True
                accept_call = True
                break
            if ((is_syn == True) & len(connection_list) != 0) | ((is_ack == True) & len(connection_list) == 0):
                isConnect = False
                send_reset = True
                break
            if ((is_ack == True) & len(connection_list) != 0):
                isConnect = True
                recv_call = True
            if (is_fin == True):
                fin_call = True

        if accept_call == True:
            global local_seq_number
            global local_ack_number
            print ack_number, seq_number
            local_seq_number = msg_rec[8]
            global seq_number
            seq_number = local_seq_number + 1
            local_seq_number = local_seq_number + 1
            print "local_seq: ", local_seq_number

            global ack_number
            ack_number = random.randint(0, 1844674407370955161)
            local_ack_number = ack_number
            print "local_ack: ", local_ack_number


            host = sock352portTx[0]
            port = sock352portTx[1]
            print host, port
            print publicKeysHex[('%s' % host, '%s' % port)]
            print privateKeysHex[('*', '*')]
            # need a method to find the local public key to use here
            local_public_key_Hex = publicKeysHex[('%s' % host, '%s' % port)]
            # need a method to find the local private key
            local_private_key_Hex = privateKeysHex[('*', '*')]

            try:
                local_public_key = nacl.public.PublicKey(local_private_key_Hex, encoder=nacl.encoding.HexEncoder)
            except TypeError:
                print "Error decoding the key"

            try:
                local_private_key = nacl.public.PrivateKey(local_private_key_Hex, encoder=nacl.encoding.HexEncoder)

            except TypeError:
                print "Error decoding the key"
            header = self.__prepare_header(0x05, ack_number, seq_number, len(local_public_call))
            message = header + local_public_key
            len_of_key = msg_rec[11] + 40
            incoming_public_key = bytesreceived[40:len_of_key]
            global server_box
            server_box = Box(local_private_key, incoming_public_key)

            print ("Package Preview inside get_Pack: %s %s %s %s  %s %s %s %s  %s %s %s %s "
                   % (struct.unpack('!BBBBHHLLQQLL', header)))
            sock.sendto(message, (sock352portTx))

            global connection_list
            connection_list.append((seq_number - 1, ack_number))

        if recv_call == True:
            global local_seq_number
            global local_ack_number
            global fragment_list
            fragment_list.put(bytesreceived[40:len(bytesreceived)])

            print ack_number, seq_number
            # if (local_seq_number == msg_rec[8] & local_ack_number+1 == msg_rec[9]):
            local_seq_number = msg_rec[8] + 1
            local_ack_number = msg_rec[9]

            header = self.__prepare_header(0x04, local_ack_number, local_seq_number, 0)
            print ("Package Preview inside get_Pack: %s %s %s %s  %s %s %s %s  %s %s %s %s "
                   % (struct.unpack('!BBBBHHLLQQLL', header)))
            sock.sendto(header, (sock352portTx))

        # call __sock352_get_packet() to get packets (polling)
        # check the list of received fragements
        # copy up to bytes_to_receive into a buffer
        # return the buffer if there is some data



        return addr

    def __prepare_header(self, flags, seq_number, ack_number, payload_len):
        print >> sys.stderr, '\tRUNNING instance _prepare_header() ... '
        sock352PktHdrData = '!BBBBHHLLQQLL'

        udpPkt_hdr_data = struct.Struct(sock352PktHdrData)

        version = 0x1

        global syn, fin, ack, reset, has_opt
        syn = 0x01  # 0x01 | 0x04 = 5
        fin = 0x02
        ack = 0x04
        reset = 0x08
        has_opt = 0x10

        opt_ptr = 0x0
        protocol = 0x0

        header_len = 0x28  # H
        checksum = 0x0

        source_port = 0x0  # L
        dest_port = 0x0

        window = 0x0  # L

        header_packed = udpPkt_hdr_data.pack(version, flags, opt_ptr, protocol,  # B
                                             header_len, checksum,  # H
                                             source_port, dest_port,  # L
                                             seq_number, ack_number,  # Q
                                             window, payload_len)  # L

        print ("Package Preview: %s %s %s %s  %s %s %s %s  %s %s %s %s "
               % (struct.unpack('!BBBBHHLLQQLL', header_packed)))

        return header_packed



