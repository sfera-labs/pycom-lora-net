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

__version__ = '0.1.0'

################################################################################
## Network layer
################################################################################

class Node:
    def __init__(self, unit_addr):
        self._net = None # set when added to net
        self._unit_addr = unit_addr
        self._lora_stats = None
        self._session = None
        self._counter_send = 0
        self._counter_recv = -1
        self._reset_trial = 0
        self._reset_next = time.ticks_ms()
        self._reset_session = None

    def send(self, msg_type, data):
        self._net._send(self, msg_type, data)

    def lora_stats(self):
        return self._lora_stats

class LoRaNet:
    _MSG_RST_1 = const(0)
    _MSG_RST_2 = const(1)
    _MSG_RST_3 = const(2)
    _MSG_RST_4 = const(3)

    def __init__(self, lora, site_id, crypto_key):
        self._lora = lora
        self._site_id = site_id
        self._unit_addr = None
        self._crypto_key = crypto_key
        self._nodes = {}
        self._reset_timeout = None

    def add_node(self, node):
        self._nodes[node._unit_addr] = node
        node._net = self

    def _start(self):
        self._sock = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
        self._sock.setblocking(False)
        self._lora.callback(
            trigger=LoRa.RX_PACKET_EVENT | LoRa.TX_PACKET_EVENT | LoRa.TX_FAILED_EVENT,
            handler=self._lora_cb
        )
        self._reset()

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
                self._send_with_session(node, node._reset_session, _MSG_RST_1, None)
                return

        Timer.Alarm(self._reset, 2)

    def _lora_cb(self, lora):
        try:
            events = lora.events()
            if events & LoRa.RX_PACKET_EVENT:
                self._recv()

            if events & LoRa.TX_PACKET_EVENT:
                print("_lora_cb sent")

            if events & LoRa.TX_FAILED_EVENT:
                print("_lora_cb fail")

        except Exception as e:
            print("LoRa CB error:", e)
            #raise e

    def _send(self, to, msg_type, data):
        self._send_with_session(to, to._session, msg_type, data)

    def _send_with_session(self, to, session, msg_type, data):
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
        while True:
            p = self._sock.recv(128)
            p_len = len(p)
            if p_len == 0:
                break

            print("recv:", p)

            site_id_len = len(self._site_id)
            if (p_len >= (site_id_len + 16) and p[:site_id_len] == self._site_id):
                iv = p[site_id_len:2 + site_id_len] * 8
                aes = AES(self._crypto_key, AES.MODE_CBC, iv)
                plain = aes.decrypt(p[2 + site_id_len:])

                print("plain:", plain)

                to_addr = plain[0]
                from_addr = plain[1]

                if to_addr == from_addr:
                    print("Error: from == to")
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
                        sender._lora_stats = self._lora.stats()
                        self._process_message(sender, msg_type, sent_session, sent_counter, data)

    def _process_message(self, sender, msg_type, sent_session, sent_counter, data):
        print("_process_message:", sender._unit_addr, msg_type, sent_session, sent_counter, data)

        if msg_type <= _MSG_RST_4:
            self._process_reset(sender, msg_type, sent_session, sent_counter, data)

        elif sender._session == sent_session and sender._counter_recv < sent_counter:
            sender._counter_recv = sent_counter
            sender._process_message(msg_type, data)

    def _process_reset(self, sender, msg_type, sent_session, sent_counter, data):
        if msg_type == _MSG_RST_1:
            print("RST 1", sender._unit_addr)

            counter_challenge = (sender._counter_recv + 1) % 0x10000
            if counter_challenge > 0xfffa:
                counter_challenge = 0
            counter_challenge = struct.pack('>H', counter_challenge)

            sender._reset_session = sent_session

            self._send_with_session(sender, sender._reset_session, _MSG_RST_2, counter_challenge)

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

            self._send_with_session(sender, sender._reset_session, _MSG_RST_3, None)

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

            self._send_with_session(sender, sender._reset_session, _MSG_RST_4, None)

            sender._session = sender._reset_session
            sender._counter_recv = sent_counter

            sender._reset_session = None
            sender._reset_next = None

            sender._on_session_reset()

            print("RST DONE!")

        elif msg_type == _MSG_RST_4:
            print("RST 4", sender._unit_addr)

            if sender._reset_session != sent_session:
                print("RST 4 error: session")
                return

            if sender._counter_recv >= sent_counter:
                print("RST 4 error: counter")
                return

            sender._counter_recv = sent_counter

            sender._reset_session = None
            sender._reset_next = None

            sender._on_session_reset()

            print("RST DONE!")

            self._reset_timeout.cancel()
            Timer.Alarm(self._reset, 1)

################################################################################
## Master-Slave layer
################################################################################

class LocalUnit:

    def __init__(self, net, unit_addr):
        self._net = net
        self._net._unit_addr = unit_addr

    def start(self):
        self._net._start()

class RemoteUnit(Node):

    _MSG_UPD = const(10)
    _MSG_CMD = const(11)
    _MSG_ACK = const(12)

    def __init__(self, unit_addr):
        super().__init__(unit_addr)

#### Master side ####

class Master(LocalUnit):
    def __init__(self, net):
        super().__init__(net, 0)

    def add_slave(self, remote_slave):
        self._net.add_node(remote_slave)

class RemoteSlave(RemoteUnit):
    def __init__(self, unit_addr):
        super().__init__(unit_addr)
        self._last_update_ts = None
        self._outputs = []
        self._cmd_timeout = None

    def state_age(self):
        if self._last_update_ts == None:
            return None
        else:
            return time.ticks_diff(self._last_update_ts, time.ticks_ms()) // 1000

    def _on_session_reset(self):
        pass

    def _send_cmd(self):
        print("RemoteSlave._send_cmd")
        try:
            if self._cmd_timeout != None:
                self._cmd_timeout.cancel()
            self.send(_MSG_CMD, self._get_cmd_data())
            self._cmd_timeout = Timer.Alarm(self._check_cmd_success, 5)

        except Exception as e:
            print("Command error:", e)

    def _process_message(self, msg_type, data):
        if msg_type == _MSG_UPD:
            print("RemoteSlave._process_message UPD")
            self._last_update_ts = time.ticks_ms()
            self._update_state(data)
            self.send(_MSG_ACK, data) # send ack
            if self._cmd_timeout != None:
                self._cmd_timeout.cancel()
            self._cmd_timeout = Timer.Alarm(self._check_cmd_success, 0.3)

    def _check_cmd_success(self, alarm):
        for out in self._outputs:
            if out._cmd_value != None and out._cmd_value != out._value:
                self._send_cmd()
                return

class RemoteOutput:
    def __init__(self, remote_slave, val_range):
        self._remote_slave = remote_slave
        self._val_range = val_range
        self._value = None
        self._cmd_value = None
        self._remote_slave._outputs.append(self)

    def __call__(self, val=None):
        if val is None:
            return self._value
        elif val in self._val_range:
            self._cmd_value = val
            self._remote_slave._send_cmd()

class RemoteInput:
    def __init__(self, unit):
        self._unit = unit
        self._value = None

    def __call__(self):
        return self._value

#### Slave side ####

class LocalSlave(LocalUnit):
    def __init__(self, net, unit_addr, unit_io, in_filter=None):
        super().__init__(net, unit_addr)
        self._io = unit_io
        if in_filter:
            self._filter = in_filter
        else:
            self._filter = self._io.filter()

        self._master = RemoteMaster(self)
        self._net.add_node(self._master)

    def start(self):
        super().start()
        _thread.start_new_thread(self._monitor, ())

    def _monitor(self):
        while True:
            try:
                if len(self._filter.process()) > 0:
                    print("LocalSlave._monitor update")
                    self._send_update()

                if self._master._needs_repetition_or_heartbeat():
                    print("LocalSlave._monitor repeat")
                    self._send_update()

            except Exception as e:
                print("Monitor error:", e)

            time.sleep(0.01)

    def _send_update(self, alarm=None):
        self._master._send_update(self._get_state_data())

class RemoteMaster(RemoteUnit):
    def __init__(self, local_slave):
        super().__init__(0)
        self._local_slave = local_slave
        self._last_update_data = None
        self._last_update_ts = None
        self._last_update_ack = None

    def _on_session_reset(self):
        Timer.Alarm(self._local_slave._send_update, 0.3)

    def _send_update(self, data):
        print("RemoteMaster._send_update", data)
        self._last_update_data = data
        self._last_update_ts = time.ticks_ms()
        self.send(_MSG_UPD, data)

    def _process_message(self, msg_type, data):
        if msg_type == _MSG_ACK:
            print("RemoteMaster._process_message ACK")
            self._last_update_ack = data

        elif msg_type == _MSG_CMD:
            print("RemoteMaster._process_message CMD")
            self._local_slave._set_state(data)

    def _needs_repetition_or_heartbeat(self):
        return (self._last_update_ack != self._last_update_data and \
            time.ticks_diff(self._last_update_ts, time.ticks_ms()) >= 5000) or \
            time.ticks_diff(self._last_update_ts, time.ticks_ms()) >= 60000

################################################################################
## Iono layer
################################################################################

class IonoRemoteSlave(RemoteSlave):
    def __init__(self, unit_addr):
        super().__init__(unit_addr)
        self.DO1 = RemoteOutput(self, [0, 1])
        self.DO2 = RemoteOutput(self, [0, 1])
        self.DO3 = RemoteOutput(self, [0, 1])
        self.DO4 = RemoteOutput(self, [0, 1])
        self.AO1 = RemoteOutput(self, range(10001))
        self.DI1 = RemoteInput(self)
        self.DI2 = RemoteInput(self)
        self.DI3 = RemoteInput(self)
        self.DI4 = RemoteInput(self)
        self.DI5 = RemoteInput(self)
        self.DI6 = RemoteInput(self)
        self.AV1 = RemoteInput(self)
        self.AV2 = RemoteInput(self)
        self.AV3 = RemoteInput(self)
        self.AV4 = RemoteInput(self)
        self.AI1 = RemoteInput(self)
        self.AI2 = RemoteInput(self)
        self.AI3 = RemoteInput(self)
        self.AI4 = RemoteInput(self)

    def _update_state(self, data):
        modes_byte, dos, ao1, dis, a1, a2, a3, a4 = struct.unpack('>BBHBHHHH', data)

        mode_di1 = (modes_byte >> 7) & 1
        mode_di2 = (modes_byte >> 5) & 1
        mode_di3 = (modes_byte >> 3) & 1
        mode_di4 = (modes_byte >> 1) & 1

        mode_a1 = (modes_byte >> 6) & 1
        mode_a2 = (modes_byte >> 4) & 1
        mode_a3 = (modes_byte >> 2) & 1
        mode_a4 = modes_byte & 1

        if a1 == 0xffff:
            a1 = None

        if a2 == 0xffff:
            a2 = None

        if a3 == 0xffff:
            a3 = None

        if a4 == 0xffff:
            a4 = None

        self.DO1._value = (dos >> 3) & 1
        self.DO2._value = (dos >> 2) & 1
        self.DO3._value = (dos >> 1) & 1
        self.DO4._value = dos & 1

        self.AO1._value = ao1

        self.DI1._value = (dis >> 5) & 1 if mode_di1 == 1 else None
        self.DI2._value = (dis >> 4) & 1 if mode_di2 == 1 else None
        self.DI3._value = (dis >> 3) & 1 if mode_di3 == 1 else None
        self.DI4._value = (dis >> 2) & 1 if mode_di4 == 1 else None
        self.DI5._value = (dis >> 1) & 1
        self.DI6._value = dis & 1

        if mode_a1 == 0:
            self.AV1._value = a1
            self.AI1._value = None
        else:
            self.AV1._value = None
            self.AI1._value = a1

        if mode_a2 == 0:
            self.AV2._value = a2
            self.AI2._value = None
        else:
            self.AV2._value = None
            self.AI2._value = a2

        if mode_a3 == 0:
            self.AV3._value = a3
            self.AI3._value = None
        else:
            self.AV3._value = None
            self.AI3._value = a3

        if mode_a4 == 0:
            self.AV4._value = a4
            self.AI4._value = None
        else:
            self.AV4._value = None
            self.AI4._value = a4

    def _get_cmd_data(self):
        mask = 0x00
        dos = 0x00
        ao1 = 0

        if self.DO1._cmd_value != None:
            mask |= 0x10
            dos |= self.DO1._cmd_value << 3

        if self.DO2._cmd_value != None:
            mask |= 0x08
            dos |= self.DO2._cmd_value << 2

        if self.DO3._cmd_value != None:
            mask |= 0x04
            dos |= self.DO3._cmd_value << 1

        if self.DO4._cmd_value != None:
            mask |= 0x02
            dos |= self.DO4._cmd_value

        if self.AO1._cmd_value != None:
            mask |= 0x01
            ao1 = self.AO1._cmd_value

        return struct.pack('>BBH', mask, dos, ao1)

class IonoLocalSlave(LocalSlave):
    def __init__(self, net, unit_addr, iono_io, in_filter=None):
        super().__init__(net, unit_addr, iono_io, in_filter)

        if iono_io.AV1:
            self._modes_byte = 2
        else:
            self._modes_byte = 3

        self._modes_byte <<= 2

        if iono_io.AV2:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

        self._modes_byte <<= 2

        if iono_io.AV3:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

        self._modes_byte <<= 2

        if iono_io.AV4:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

    def _set_state(self, data):
        mask, dos, ao1 = struct.unpack('>BBH', data)

        if (mask >> 4) & 1 == 1:
            self._io.DO1((dos >> 3) & 1)

        if (mask >> 3) & 1 == 1:
            self._io.DO2((dos >> 2) & 1)

        if (mask >> 2) & 1 == 1:
            self._io.DO3((dos >> 1) & 1)

        if (mask >> 1) & 1 == 1:
            self._io.DO4(dos & 1)

        if mask & 1 == 1:
            self._io.AO1(ao1)

    def _get_state_data(self):
        dos = self._io.DO1() << 3
        dos |= self._io.DO2() << 2
        dos |= self._io.DO3() << 1
        dos |= self._io.DO4()

        ao1 = self._io.AO1()

        dis = (self._filter.DI1() if self._filter.DI1 else 0) << 5
        dis |= (self._filter.DI2() if self._filter.DI2 else 0) << 4
        dis |= (self._filter.DI3() if self._filter.DI3 else 0) << 3
        dis |= (self._filter.DI4() if self._filter.DI4 else 0) << 2
        dis |= self._filter.DI5() << 1
        dis |= self._filter.DI6()

        a1 = self._filter.AV1() if self._filter.AV1 else (self._filter.AI1() if self._filter.AI1 else 0xffff)
        a2 = self._filter.AV2() if self._filter.AV2 else (self._filter.AI2() if self._filter.AI2 else 0xffff)
        a3 = self._filter.AV3() if self._filter.AV3 else (self._filter.AI3() if self._filter.AI3 else 0xffff)
        a4 = self._filter.AV4() if self._filter.AV4 else (self._filter.AI4() if self._filter.AI4 else 0xffff)

        return struct.pack('>BBHBHHHH', self._modes_byte, dos, ao1, dis, a1, a2, a3, a4)
