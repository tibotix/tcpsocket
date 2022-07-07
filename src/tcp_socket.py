from typing import *
from scapy.all import *


class TCPConnection:
    pass


class TCPClientStateMachine(Automaton):
    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def SYN_SENT(self):
        pass

    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.state()
    def CLOSE_WAIT(self):
        pass

    @ATMT.state()
    def LAST_ACK(self):
        pass

    @ATMT.state(final=1)
    def CLOSED(self):
        pass


class TCPStateMachine(Automaton):
    def parse_args(
        self, dhost, dport, shost, sport, iface=None, timeout=3, verbose=False, **kwargs
    ):
        Automaton.parse_args(self, **kwargs)
        self.dhost = dhost
        self.dport = dport
        self.shost = shost
        self.sport = sport
        self.timeout = timeout
        self.verbose = verbose
        self.iface = iface
        self.ip = IP(dst=dhost, src=shost)

    @ATMT.state(stop=1)
    def STOP(self):
        # initiate stop
        pass

    @ATMT.state(initial=1)
    def CLOSED(self):
        # 1. Passive Open -> Listen
        # 2. Active Open -> Connect
        pass

    @ATMT.condition(CLOSED)
    def active_opened(self):
        if self.active_open:
            raise self.SYN_SENT()

    @ATMT.action(active_opened)
    def send_handshake_syn(self):
        self.seq = random.randrange(0, (2 ** 32) - 1)
        syn = self.ip / TCP(sport=self.sport, dport=self.dport, seq=self.seq, flags="S")
        self.send(syn)
        self.seq += 1
        # syn_ack = sr1(syn, timeout=self._timeout, verbose=self.verbose)

    @ATMT.state()
    def LISTEN(self):
        pass

    @ATMT.receive_condition(LISTEN)
    def handshake_syn_received(self, syn):
        if syn.haslayer(TCP) and syn[TCP].flags & 0x10 == 0x10:
            raise self.SYN_RECEIVED().action_parameters(syn)

    @ATMT.action(handshake_syn_received_syn_sent)
    @ATMT.action(handshake_syn_received)
    def send_handshake_syn_ack(self, syn):
        self.seq = random.randrange(0, (2 ** 32) - 1)
        self.ack = syn[TCP].seq + 1
        syn_ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, seq=self.seq, flags="SA", ack=self.ack
        )
        self.send(syn_ack)
        self.seq += 1

    @ATMT.state()
    def SYN_RECEIVED(self):
        pass

    @ATMT.receive_condition(SYN_RECEIVED)
    def handshake_ack_received(self, ack):
        if (
            ack.haslayer(TCP)
            and ack[TCP].flags & 0x2 == 0x2
            and ack[TCP].ack == self.seq
        ):
            raise self.ESTABLISHED()

    @ATMT.state()
    def SYN_SENT(self):
        pass

    @ATMT.receive_condition(SYN_SENT)
    def handshake_syn_received_syn_sent(self, syn):
        if syn.haslayer(TCP) and syn[TCP].flags & 0x10 == 0x10:
            raise self.SYN_RECEIVED().action_parameters(syn)

    @ATMT.receive_condition(SYN_SENT)
    def handshake_syn_ack_received(self, syn_ack):
        if (
            syn_ack.haslayer(TCP)
            and syn_ack[TCP].flags & 0x12 == 0x12
            and syn_ack[TCP].ack == self.seq
        ):
            raise self.ESTABLISHED().action_parameters(syn_ack)

    @ATMT.action(handshake_syn_ack_received)
    def send_handshake_ack(self, syn_ack):
        self.ack = syn_ack[TCP].seq + 1
        ack = self.ip / TCP(
            sport=self.sport, dport=self.dport, seq=self.seq, flags="A", ack=self.ack
        )
        self.send(ack, verbose=self.verbose)
        print("Connected")

    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.state()
    def FIN_WAIT_1(self):
        pass

    @ATMT.state()
    def FIN_WAIT_2(self):
        pass

    @ATMT.state()
    def CLOSING(self):
        pass

    @ATMT.state()
    def TIME_WAIT(self):
        pass

    @ATMT.state()
    def CLOSE_WAIT(self):
        pass

    @ATMT.state()
    def LAST_ACK(self):
        pass


class TCPSocket:
    def __init__(self) -> None:
        pass

    def connect(self, host, port):
        pass

    def bind(self, host, port):
        pass

    def listen(self):
        pass

    def accept(self) -> Tuple[TCPSocket, str]:
        pass

    def setsockopt(self, level, optname, value):
        pass

    def settimeout(self, value):
        # Set a timeout on blocking socket operations
        pass

    def send(self, msg):
        pass

    def recv(self, bufsize):
        pass
