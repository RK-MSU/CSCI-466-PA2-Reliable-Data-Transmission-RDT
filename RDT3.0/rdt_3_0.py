# rdt_3_0.py

from datetime import datetime, timedelta
import network_3_0 as Network
import argparse
from time import sleep
import hashlib
import threading
import logging

log_lvl = logging.CRITICAL # logging.DEBUG, logging.INFO
logging.basicConfig(format='%(levelname)s - %(asctime)s: %(message)s', datefmt='%I:%M:%S %p', level=log_lvl)

class RDTException(Exception):
    pass

class RDTPacketCorruptionError(RDTException):
    pass

class RDTReceiveTimeoutError(RDTException):
    pass

class Packet:
    # the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    # length of md5 checksum in hex
    checksum_length = 32
    
    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S
    
    @classmethod
    def from_byte_S(cls, byte_S):
        if Packet.corrupt(byte_S):
            raise RDTPacketCorruptionError('Cannot initialize Packet: byte_S is corrupt')
        # extract the fields
        seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        return cls(seq_num, msg_S)
    
    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
            self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S
    
    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length]
        checksum_S = byte_S[
                     Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length]
        msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
        
        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S
    
    @staticmethod
    def isACK(packet):
        if packet.msg_S == 'ACK': return True
        return False

    @staticmethod
    def isNAK(packet):
        if packet.msg_S == 'NAK': return True
        return False


class RDT:
    # unidirectional network links
    net_snd = None # sending
    net_rcv = None # receiving
    # receive timeout
    timeout = timedelta(seconds=1)
    # latest sequence number used in a packet
    seq_num = 1
    # buffer of bytes read from network
    byte_buffer = ''
    # theading properties
    active_sender = threading.Event()
    lock = threading.Lock() # ensure synchronized data
    stop = None # when True, terminate receive help thread loop
    receive_helper_thread = None

    upstream_packet_queue = list()
    acknowledgement_packet_queue = list()
    last_sent_packet = None
    last_acknowledged_seq_num = None
    sending_timer = None
    
    def __init__(self, role_S, server_S, port):
        # use the passed in port and port+1 to set up unidirectional links between
        # RDT send and receive functions
        # cross the ports on the client and server to match net_snd to net_rcv
        if role_S == 'server':
            self.net_snd = Network.NetworkLayer(role_S, server_S, port)
            self.net_rcv = Network.NetworkLayer(role_S, server_S, port + 1)
        else:
            self.net_rcv = Network.NetworkLayer(role_S, server_S, port)
            self.net_snd = Network.NetworkLayer(role_S, server_S, port + 1)
        # start the receive helper thread
        self.receive_helper_thread = threading.Thread(name="ReceiveHelperThread", target=self.__receive_helper, daemon=True)
        self.stop = False
        self.receive_helper_thread.start()
        # EOF __init__()

    def disconnect(self):
        # if the sender is done, but the server is expecting
        # a resent ACK due to corruption, we don't want the
        # server to be stuck in a rdt_send locking state
        # So, lets delay termination to ensure parties receive
        # any expected ACKs
        sleep(5)
        if self.receive_helper_thread:
            self.stop = True
            self.receive_helper_thread.join()
        # disconnect sending link
        self.net_snd.disconnect()
        del self.net_snd
        # disconnect receiving link
        self.net_rcv.disconnect()
        del self.net_rcv
        logging.info('Disconnected')
        # EOF disconnect()
    
    def udt_send(self, packet):
        self.net_snd.udt_send(packet.get_byte_S())
        # EOF udt_send()
    
    def udt_receive(self):
        return self.net_rcv.udt_receive()
        # EOF udt_receive()

    def send_NAK(self, seq_num = None):
        if seq_num == None:
            seq_num = self.seq_num
        self.udt_send(Packet(seq_num, 'NAK'))
        # EOF send_NAK()
    
    def send_ACK(self, seq_num = None):
        if seq_num == None:
            seq_num = self.seq_num
        self.udt_send(Packet(seq_num, 'ACK'))
        # EOF send_ACK()
    
    def rdt_3_0_send(self, msg_S):
        # create send packet
        sndpkt = Packet(self.seq_num, msg_S)
        with self.lock:
            self.last_sent_packet = sndpkt
            self.active_sender.set()
            self.acknowledgement_packet_queue = list()
            self.sending_timer = datetime.now()
        # send packet
        logging.info('Sending packet')
        self.udt_send(sndpkt)
        while True:
            with self.lock:
                if datetime.now() - self.sending_timer > timedelta(seconds=0.2):
                    logging.info('Sender timeout - packet loss - resending....')
                    self.udt_send(sndpkt)
                    self.sending_timer = datetime.now()
            rcvpkt = None
            with self.lock:
                if len(self.acknowledgement_packet_queue) > 0:
                    rcvpkt = self.acknowledgement_packet_queue.pop(0)
                else:
                    continue
                if rcvpkt is None: continue
                # check of NAK
                if Packet.isNAK(rcvpkt):
                    logging.info('Received NAK, resending packet')
                    self.udt_send(sndpkt)
                    start = datetime.now()
                    continue
                # check for ACK
                if Packet.isACK(rcvpkt) and sndpkt.seq_num == rcvpkt.seq_num:
                    logging.info('Received ACK')
                    self.active_sender.clear()
                    self.acknowledgement_packet_queue = list()
                    self.sending_timer = None
                    self.seq_num += 1
                    return
                logging.warning('Something happened...')
        # EOF rdt_3_0_send()
    
    def rdt_3_0_receive(self):
        start = datetime.now()
        while True:
            if datetime.now() - start > self.timeout:
                raise RDTReceiveTimeoutError('timeout')
            # received packet
            with self.lock:
                if len(self.upstream_packet_queue) > 0:
                    logging.info('Received packet')
                    rcvpkt = self.upstream_packet_queue.pop(0)
                    # self.upstream_packet_queue = list() # TODO: need this?
                    return rcvpkt.msg_S
        # EOF rdt_3_0_receive()
    
    def __receive_helper(self):
        while True:
            if self.stop: break # stop receive_helper thread
            with self.lock:
                self.__auto_receive()
    # EOF __receive_helper()

    def __auto_receive(self):
        byte_S = self.udt_receive()
        self.byte_buffer += byte_S
        # check if we have received enough bytes
        if len(self.byte_buffer) < Packet.length_S_length:
            # not enough bytes to read packet length
            return None
         # extract length of packet
        length = int(self.byte_buffer[:Packet.length_S_length])
        if len(self.byte_buffer) < length:
            # not enough bytes to read the whole packet
            return None
        # get the packet's bytes from the buffer
        rcv_pkt_bytes_S = self.byte_buffer[0:length]
        # remove the packet bytes from the buffer
        self.byte_buffer = self.byte_buffer[length:]
        # check if packet is corrupt
        if Packet.corrupt(rcv_pkt_bytes_S):
            logging.info('Received corrupt packet')
            self.send_NAK()
            if self.active_sender.is_set():
                self.udt_send(self.last_sent_packet)
                self.sending_timer = datetime.now()
            return None
        # make the received packet
        rcvpkt = Packet.from_byte_S(rcv_pkt_bytes_S)
        # is the received pack a type of acknowledgement? (ACK/NAK)
        if Packet.isACK(rcvpkt) or Packet.isNAK(rcvpkt):
            self.acknowledgement_packet_queue.append(rcvpkt)
            return None
        if self.last_acknowledged_seq_num is not None and rcvpkt.seq_num <= self.last_acknowledged_seq_num:
            logging.debug('Resending ACK')
            self.send_ACK(self.last_acknowledged_seq_num)
            return None
        self.last_acknowledged_seq_num = rcvpkt.seq_num
        logging.info('Sending ACK')
        self.send_ACK(rcvpkt.seq_num)
        self.upstream_packet_queue.append(rcvpkt)
        return rcvpkt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()
    
    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()
    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()

# EOF