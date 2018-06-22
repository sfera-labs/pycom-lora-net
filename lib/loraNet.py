from network import LoRa
import socket
from crypto import AES
import crypto
import time
import _thread
import struct
from machine import Timer

class LoRaNet:

    def __init__(self, lora, site_id, crypto_key):
        self._lora = lora
        self._site_id = site_id
        self._crypto_key = crypto_key
        self._local_unit = None
        self._net_units = {}

    def set_local_unit(self, unit):
        self._local_unit = unit
        unit._lora_net = self

    def add_net_unit(self, unit):
        self._net_units[unit._unit_addr] = unit
        unit._lora_net = self

    def start(self):
        self._sock = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
        self._sock.setblocking(False)
        self._lora.callback(
            trigger=LoRa.RX_PACKET_EVENT | LoRa.TX_PACKET_EVENT | LoRa.TX_FAILED_EVENT,
            handler=self._lora_cb
        )
        if self._local_unit:
            _thread.start_new_thread(self._local_unit._monitor, ())
            Timer.Alarm(self._local_unit._periodic_broadcast, self._local_unit._broadcast_period, periodic=True)

    def _lora_cb(self, lora):
        try:
            events = lora.events()
            if events & LoRa.RX_PACKET_EVENT:
                p = self._sock.recv(128)
                print("recv:", p)
                site_id_len = len(self._site_id)
                if (len(p) > site_id_len and p[:site_id_len] == self._site_id):
                    iv = p[site_id_len:16 + site_id_len]
                    cipher = AES(self._crypto_key, AES.MODE_CBC, iv)
                    data = cipher.decrypt(p[16 + site_id_len:])
                    print("data:", data)
                    unit_addr = data[0]
                    if unit_addr == 0:
                        unit = self._net_units[data[1]]
                        if unit:
                            unit._update(data[2:])
                            unit._lora_stats = lora.stats()

                    elif self._local_unit and self._local_unit._unit_addr == unit_addr:
                        self._local_unit._update(data[1:])

            elif events & LoRa.TX_PACKET_EVENT:
                print("lora sent")

            elif events & LoRa.TX_FAILED_EVENT:
                print("lora fail")

        except Exception as e:
            print("LoRa CB error:", e)

    def send(self, data):
        pads = (16 - (len(data) % 16)) % 16
        data += pads * '='
        print("sending:", data)
        iv = crypto.getrandbits(128)
        cipher = AES(self._crypto_key, AES.MODE_CBC, iv)
        self._sock.send(self._site_id + iv + cipher.encrypt(data))

class NetAttribute:
    def __init__(self, net_unit, id):
        self._net_unit = net_unit
        self._id = id
        self._value = None

    def __call__(self, val=None):
        if val is None:
            return self._value
        else:
            self._net_unit._req_update(self._id, val)

class NetUnit:
    def __init__(self, unit_addr):
        self._unit_addr = unit_addr
        self._lora_stats = None
        self._last_update = None

    def lora_stats(self):
        return self._lora_stats

    def _update(self, data):
        self._last_update = time.ticks_ms()

    def state_age(self):
        if self._last_update == None:
            return None
        else:
            return time.ticks_diff(self._last_update, time.ticks_ms()) // 1000

    def _req_update(self, id, val):
        data = bytearray()
        data.append(self._unit_addr)
        pl = "{}={}".format(id, val)
        data.extend(pl)
        self._lora_net.send(data)

class IonoNet(NetUnit):
    def __init__(self, unit_addr):
        super().__init__(unit_addr)
        self.DO1 = NetAttribute(self, 'DO1')
        self.DO2 = NetAttribute(self, 'DO2')
        self.DO3 = NetAttribute(self, 'DO3')
        self.DO4 = NetAttribute(self, 'DO4')
        self.DI1 = NetAttribute(self, 'DI1')
        self.DI2 = NetAttribute(self, 'DI2')
        self.DI3 = NetAttribute(self, 'DI3')
        self.DI4 = NetAttribute(self, 'DI4')
        self.DI5 = NetAttribute(self, 'DI4')
        self.DI6 = NetAttribute(self, 'DI4')
        self.AV1 = NetAttribute(self, 'AV1')
        self.AV2 = NetAttribute(self, 'AV2')
        self.AV3 = NetAttribute(self, 'AV3')
        self.AV4 = NetAttribute(self, 'AV4')
        self.AI1 = NetAttribute(self, 'AI1')
        self.AI2 = NetAttribute(self, 'AI2')
        self.AI3 = NetAttribute(self, 'AI3')
        self.AI4 = NetAttribute(self, 'AI4')
        self.AO1 = NetAttribute(self, 'AO1')

    def _update(self, data):
        super()._update(data)

        modes_byte, dos, ao1, dis, a1, a2, a3, a4 = struct.unpack('>BBHBHHHH', data)

        mode1 = (modes_byte >> 6) & 3
        mode2 = (modes_byte >> 4) & 3
        mode3 = (modes_byte >> 2) & 3
        mode4 = modes_byte & 3

        self.DO1._value = (dos >> 3) & 1
        self.DO2._value = (dos >> 2) & 1
        self.DO3._value = (dos >> 1) & 1
        self.DO4._value = dos & 1

        self.AO1._value = ao1

        if mode1 == 1:
            self.DI1._value = (dis >> 5) & 1
            self.AV1._value = None
            self.AI1._value = None
        elif mode1 == 2:
            self.DI1._value = None
            self.AV1._value = a1
            self.AI1._value = None
        else:
            self.DI1._value = None
            self.AV1._value = None
            self.AI1._value = a1

        if mode2 == 1:
            self.DI2._value = (dis >> 4) & 1
            self.AV2._value = None
            self.AI2._value = None
        elif mode2 == 2:
            self.DI2._value = None
            self.AV2._value = a2
            self.AI2._value = None
        else:
            self.DI2._value = None
            self.AV2._value = None
            self.AI2._value = a2

        if mode3 == 1:
            self.DI3._value = (dis >> 3) & 1
            self.AV3._value = None
            self.AI3._value = None
        elif mode3 == 2:
            self.DI3._value = None
            self.AV3._value = a3
            self.AI3._value = None
        else:
            self.DI3._value = None
            self.AV3._value = None
            self.AI3._value = a3

        if mode4 == 1:
            self.DI4._value = (dis >> 2) & 1
            self.AV4._value = None
            self.AI4._value = None
        elif mode4 == 2:
            self.DI4._value = None
            self.AV4._value = a4
            self.AI4._value = None
        else:
            self.DI4._value = None
            self.AV4._value = None
            self.AI4._value = a4

        self.DI5._value = (dis >> 1) & 1
        self.DI6._value = dis & 1

class LocalUnit:
    def __init__(self, unit_addr, uinit_io, in_filter=None, broadcast_period=30):
        self._unit_addr = unit_addr
        self._io = uinit_io
        if in_filter:
            self._filter = in_filter
        else:
            self._filter = self._io.filter()

        self._broadcast_period = broadcast_period
        self._last_broadcast = None

    def _monitor(self):
        while True:
            try:
                if len(self._filter.process()) > 0:
                    self._broadcast_update()
                time.sleep(0.01)
            except Exception as e:
                print("Monitor error:", e)

class IonoLocal(LocalUnit):
    def __init__(self, unit_addr, iono_io, in_filter=None, broadcast_period=30):
        super().__init__(unit_addr, iono_io, in_filter, broadcast_period)

        if iono_io.DI1:
            self._modes_byte = 1
        elif iono_io.AV1:
            self._modes_byte = 2
        else:
            self._modes_byte = 3

        self._modes_byte <<= 2

        if iono_io.DI2:
            self._modes_byte |= 1
        elif iono_io.AV2:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

        self._modes_byte <<= 2

        if iono_io.DI3:
            self._modes_byte |= 1
        elif iono_io.AV3:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

        self._modes_byte <<= 2

        if iono_io.DI4:
            self._modes_byte |= 1
        elif iono_io.AV4:
            self._modes_byte |= 2
        else:
            self._modes_byte |= 3

    def _update(self, data):
        id_val = data.decode().split('=')
        for out in self._io.all:
            if out.id() == id_val[0]:
                out(int(id_val[1]))
                break

    def _periodic_broadcast(self, alarm):
        if self._last_broadcast == None or time.ticks_diff(self._last_broadcast, time.ticks_ms()) > self._broadcast_period * 1000 // 2:
            self._broadcast_update()

    def _broadcast_update(self):
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

        a1 = self._filter.AV1() if self._filter.AV1 else (self._filter.AI1() if self._filter.AI1 else 0)
        a2 = self._filter.AV2() if self._filter.AV2 else (self._filter.AI2() if self._filter.AI2 else 0)
        a3 = self._filter.AV3() if self._filter.AV3 else (self._filter.AI3() if self._filter.AI3 else 0)
        a4 = self._filter.AV4() if self._filter.AV4 else (self._filter.AI4() if self._filter.AI4 else 0)

        data = struct.pack('>BBBBHBHHHH', 0, self._unit_addr, self._modes_byte, dos, ao1, dis, a1, a2, a3, a4)

        self._lora_net.send(data)

        self._last_broadcast = time.ticks_ms()
