from network import LoRa
import socket
from crypto import AES
import crypto
import crc as CRC
import time
import _thread
import struct
import machine
from machine import Timer
import pycom

class Node:
    def __init__(self, unit_addr):
        self._unit_addr = unit_addr
        self._lora_stats = None
        self._last_update = None
        self._session = None
        self._counter_send = 0
        self._counter_recv = -1
        self._reset_trial = 0
        self._reset_next = time.ticks_ms()
        self._reset_session = None

class LoRaNet:
    _MSG_RST_1 = const(0)
    _MSG_RST_2 = const(1)
    _MSG_RST_3 = const(2)
    _MSG_RST_4 = const(3)

    _MSG_UPD = const(10)
    _MSG_CMD = const(11)

    def __init__(self, lora, site_id, crypto_key):
        self._lora = lora
        self._site_id = site_id
        self._unit_addr = None
        self._crypto_key = crypto_key
        self._nodes = {}
        self._reset_timeout = None

    def add_node(self, node):
        self._nodes[node._unit_addr] = node

    def start_gw(self):
        self._unit_addr = 0
        self._start()

    def start_node(self, unit_addr):
        self._unit_addr = unit_addr
        self.add_node(Node(0))
        self._start()

    def send_cmd(self, unit_addr, data):
        node = self._nodes[unit_addr]
        self._send(node, node._session, _MSG_CMD, data)

    def send_update(self, data):
        gw = self._nodes[0]
        self._send(gw, gw._session, _MSG_UPD, data)

    def _start(self):
        self._sock = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
        self._sock.setblocking(False)
        self._lora.callback(
            trigger=LoRa.RX_PACKET_EVENT | LoRa.TX_PACKET_EVENT | LoRa.TX_FAILED_EVENT,
            handler=self._lora_cb
        )
        self._reset()
        # if self._local_unit:
        #    _thread.start_new_thread(self._local_unit._monitor, ())
        #    Timer.Alarm(self._local_unit._periodic_broadcast, self._local_unit._broadcast_period, periodic=True)

    def _lora_cb(self, lora):
        try:
            events = lora.events()
            if events & LoRa.RX_PACKET_EVENT:
                self._recv()

            elif events & LoRa.TX_PACKET_EVENT:
                print("_lora_cb sent")

            elif events & LoRa.TX_FAILED_EVENT:
                print("_lora_cb fail")

        except Exception as e:
            print("LoRa CB error:", e)
            #raise e

    def _send(self, to, session, msg_type, data):
        print("_send:", to._unit_addr, msg_type, session, to._counter_send, data)

        if session == None:
            raise Exception('No session')

        plain = bytearray()
        plain.append(to._unit_addr)
        plain.append(self._unit_addr)
        plain.append(msg_type)
        plain.extend(session)
        plain.extend(struct.pack('>H', to._counter_send))
        if data:
            plain.append(len(data))
            plain.extend(data)
        else:
            plain.append(0)

        plain.extend(CRC.crc16(plain))

        pads = (16 - (len(plain) % 16)) % 16
        plain.extend(pads * '=')

        print("sending:", plain)

        iv = crypto.getrandbits(32)[:2]
        aes = AES(self._crypto_key, AES.MODE_CBC, iv * 8)
        self._sock.send(self._site_id + iv + aes.encrypt(plain))

        to._counter_send = (to._counter_send + 1) % 0x10000
        if to._counter_send == 0:
            print("Reset after counter overflow")
            to._reset_trial = 0
            to._reset_next = time.ticks_ms()

    def _recv(self):
        p = self._sock.recv(128)
        print("recv:", p)
        site_id_len = len(self._site_id)
        if (len(p) >= (site_id_len + 16) and p[:site_id_len] == self._site_id):
            iv = p[site_id_len:2 + site_id_len] * 8
            aes = AES(self._crypto_key, AES.MODE_CBC, iv)
            plain = aes.decrypt(p[2 + site_id_len:])

            print("plain:", plain)

            to_addr = plain[0]
            from_addr = plain[1]

            if to_addr == from_addr:
                print("Error: from == to")
                return

            if from_addr != 0 and to_addr != 0:
                print("Error: node to node")
                return

            msg_type = plain[2]
            sent_session = plain[3:11]
            sent_counter = struct.unpack('>H', plain[11:13])[0]
            data_len = plain[13]
            if data_len > 0:
                data = plain[14:14 + data_len]
            else:
                data = None

            crc = plain[14 + data_len:14 + data_len + 2]
            if crc != CRC.crc16(plain[:14 + data_len]):
                print("Error: crc")
                return

            if self._unit_addr == to_addr:
                sender = self._nodes[from_addr]
                if sender:
                    self._process_message(sender, msg_type, sent_session, sent_counter, data)

    def _process_message(self, sender, msg_type, sent_session, sent_counter, data):
        print("_process_message:", sender._unit_addr, msg_type, sent_session, sent_counter, data)

        if sender._session == sent_session:
            if sender._counter_recv < sent_counter:

                if msg_type == _MSG_UPD:
                    sender._counter_recv = sent_counter
                    print("** GOT UPDATE **")
                    return

                elif msg_type == _MSG_CMD:
                    sender._counter_recv = sent_counter
                    print("** GOT COMMAND **")
                    return

        self._process_reset(sender, msg_type, sent_session, sent_counter, data)

    def _reset(self, alarm=None):
        now = time.ticks_ms()
        for addr, node in self._nodes.items():
            if node._reset_next != None and time.ticks_diff(node._reset_next, now) >= 0:
                print("_reset", node._unit_addr)
                node._reset_next = time.ticks_add(now, node._reset_trial * 5000 + (machine.rng() % 5000))
                if node._reset_trial < 30:
                    node._reset_trial += 1
                self._reset_timeout = Timer.Alarm(self._reset, 5)
                node._reset_session = crypto.getrandbits(64)
                self._send(node, node._reset_session, _MSG_RST_1, None)
                return

        Timer.Alarm(self._reset, 2)

    def _process_reset(self, sender, msg_type, sent_session, sent_counter, data):
        if msg_type == _MSG_RST_1:
            print("RST 1", sender._unit_addr)

            counter_challenge = (sender._counter_recv + 1) % 0x10000
            if counter_challenge > 0xfffa:
                counter_challenge = 0
            counter_challenge = struct.pack('>H', counter_challenge)

            sender._reset_session = sent_session

            self._send(sender, sender._reset_session, _MSG_RST_2, counter_challenge)

        elif msg_type == _MSG_RST_2:
            print("RST 2", sender._unit_addr)

            if sender._reset_session != sent_session:
                print("RST 2 error: session")
                return

            if sender._counter_recv >= sent_counter:
                print("RST 2 error: counter")
                return

            counter_challenge = struct.unpack('>H', data[0:2])[0]
            sender._counter_send = counter_challenge

            self._send(sender, sender._reset_session, _MSG_RST_3, None)

            sender._session = sender._reset_session
            sender._counter_recv = sent_counter

        elif msg_type == _MSG_RST_3:
            print("RST 3", sender._unit_addr)

            if sender._reset_session != sent_session:
                print("RST 3 error: session")
                return

            counter_challenge = (sender._counter_recv + 1) % 0x10000
            if counter_challenge > 0xfffa:
                counter_challenge = 0

            if sent_counter != counter_challenge:
                print("RST 3 error: counter", sent_counter, counter_challenge)
                return

            self._send(sender, sender._reset_session, _MSG_RST_4, None)

            sender._session = sender._reset_session
            sender._counter_recv = sent_counter

            sender._reset_session = None
            sender._reset_next = None

            print("RST DONE!")

        elif msg_type == _MSG_RST_4:
            print("RST 4", sender._unit_addr)

            if sender._reset_session != sent_session:
                print("RST 4 error: session")
                return

            if sender._counter_recv >= sent_counter:
                print("RST 4 error: counter")
                return

            sender._reset_session = None
            sender._reset_next = None

            print("RST DONE!")

            self._reset_timeout.cancel()
            Timer.Alarm(self._reset, 1)

        else:
            # TODO remove
            print("Discarded message:", msg_type, sent_session, sent_counter)
