
import binascii
import socket as syssock
import struct
import sys
import Queue
import time
import random
import select


def init(UDPportTx,UDPportRx):
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

    print >> sys.stderr, 'Binding to UDPportRx ... %s' % UDPportRx
    pass
    
class socket(syssock.socket):
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

    def connect(self, address):
        print >> sys.stderr, '\nRUNNING instance connect() ... '
        global seq_number
        global ack_number
        seq_number = random.randint(0, 1844674407370955161)
        ack_number = 0

        local_seq_number = seq_number
        bytesreceived = 0
        print >> sys.stderr, 'Initial Seq Number: %s' % seq_number
        print >> sys.stderr, 'Initial Ack Number: %s' % ack_number

        #def __prepare_header(self, flags, seq_number, ack_number, payload_len):

        header = self.__prepare_header(0x01, seq_number, ack_number, 0)

        SYN_acked = False
        while (SYN_acked == False):
            sock.sendto(header, (local_port_for_sending))
            print ("Message sent from connect(): %s %s %s %s  %s %s %s %s  %s %s %s %s " 
                % (struct.unpack('!BBBBHHLLQQLL', header)))
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
                % (msg_rec) )
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
            #if is_reset == True:
                #something
        print >> sys.stderr, 'About to return from connect() ... ' 
        return 

    def listen(self, backlog):
        print >> sys.stderr, '\nRUNNING instance listen(self, backlog) .... '
        return

    def accept(self):
        print >> sys.stderr, '\nRUNNING instance accept() ... '

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
        sock.close()
        return


    def send(self, buffer):
        print >> sys.stderr, '\nRUNNING instance send() ... '
        bytessent = 0     # fill in your code here 
        bytesreceived = 0

        print seq_number
        print ack_number
        global seq_number
        global ack_number
        ack_number = ack_number + 1

        header = self.__prepare_header(0x04, seq_number, ack_number, (len(buffer)))
        message = header + buffer

        ACK_receipt = False
        while (not ACK_receipt):
            sock.sendto(message, (local_port_for_sending))

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

        print 'len_bytesreceived: %d' %len(buffer)
        return len(buffer)

    def recv(self, nbytes):
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
            addr= self.__sock352_get_packet()
            temp = fragment_list.get_nowait()
            need_bytes = temp[0:nbytes]
            temp = temp[nbytes:len(temp)]
            fragment_list.put(temp)
            return need_bytes


    def __sock352_get_packet(self):
        print >> sys.stderr, '\tRUNNING instance __sock352_get_packet() ... '
        isConnect = False
        is_syn = False
        is_ack= False
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

            header = self.__prepare_header(0x05, ack_number, seq_number, 0)
            print ("Package Preview inside get_Pack: %s %s %s %s  %s %s %s %s  %s %s %s %s "
                   % (struct.unpack('!BBBBHHLLQQLL', header)))
            sock.sendto(header, (local_port_for_sending))

            global connection_list
            connection_list.append((seq_number - 1, ack_number))

        if recv_call == True:
            global local_seq_number
            global local_ack_number
            global fragment_list
            fragment_list.put(bytesreceived[40:len(bytesreceived)])

            print ack_number, seq_number
            #if (local_seq_number == msg_rec[8] & local_ack_number+1 == msg_rec[9]):
            local_seq_number = msg_rec[8] + 1
            local_ack_number = msg_rec[9]

            header = self.__prepare_header(0x04, local_ack_number, local_seq_number, 0)
            print ("Package Preview inside get_Pack: %s %s %s %s  %s %s %s %s  %s %s %s %s "
                % (struct.unpack('!BBBBHHLLQQLL', header)))
            sock.sendto(header, (local_port_for_sending))


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
        syn = 0x01#0x01 | 0x04 = 5
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


    
