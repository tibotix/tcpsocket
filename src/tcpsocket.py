from scapy.all import *
import enum
import queue
import threading
import random


# TODO: implement SAck: https://datatracker.ietf.org/doc/html/rfc2018


# reset RST: iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# restore RST: iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP


class Callback(enum.IntEnum):
    SEND_ACK = 0


class TCPSocket:
    def __init__(self, dhost, dport, shost, sport, timeout=3, verbose=1):
        self.seq = 0
        self.ack = 0
        self.ip = IP(dst=dhost, src=shost)
        self.sport = sport
        self.dport = dport
        self.connected = False
        self._mainloop_thread = None
        self._timeout = timeout
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
        s = L3RawSocket(iface="enp0s3")
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
        syn.show()
        syn_ack = sr1(syn, timeout=self._timeout, verbose=self.verbose, iface="enp0s3")
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
