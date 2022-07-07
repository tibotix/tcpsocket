from scapy.all import *
import random


class TCP_client(Automaton):
    """
    Creates a TCP Client Automaton.
    This automaton will handle TCP 3-way handshake.
    Usage: the easiest usage is to use it as a SuperSocket.
        >>> a = TCP_client.tcplink(HTTP, "www.google.com", 80)
        >>> a.send(HTTPRequest())
        >>> a.recv()
    :param ip: the ip to connect to
    :param port:
    """

    def parse_args(self, dhost, dport, shost=None, sport=None, *args, **kargs):
        from scapy.sessions import TCPSession

        self.dst = str(Net(dhost))
        self.dhost = dhost
        self.dport = dport
        self.shost = shost
        store = kargs.get("store", False)
        self.sport = sport if sport is not None else random.randrange(0, 2 ** 16)
        self.l4 = IP(dst=self.dhost, src=self.shost) / TCP(
            sport=self.sport,
            dport=self.dport,
            flags=0,
            seq=random.randrange(0, 2 ** 32),
        )
        self.src = self.l4.src
        self.sack = self.l4[TCP].ack
        self.rel_seq = None
        self.rcvbuf = TCPSession(prn=self._transmit_packet, store=store)
        bpf = "host %s  and host %s and port %i and port %i" % (
            self.src,
            self.dst,
            self.sport,
            self.dport,
        )
        Automaton.parse_args(self, filter=bpf, **kargs)

    def _transmit_packet(self, pkt):
        """Transmits a packet from TCPSession to the SuperSocket"""
        self.oi.tcp.send(raw(pkt[TCP].payload))

    def master_filter(self, pkt):
        return (
            IP in pkt
            and pkt[IP].src == self.dst
            and pkt[IP].dst == self.src
            and TCP in pkt
            and pkt[TCP].sport == self.dport
            and pkt[TCP].dport == self.sport
            and self.l4[TCP].seq >= pkt[TCP].ack
            and (  # XXX: seq/ack 2^32 wrap up  # noqa: E501
                (self.l4[TCP].ack == 0)
                or (self.sack <= pkt[TCP].seq <= self.l4[TCP].ack + pkt[TCP].window)
            )
        )  # noqa: E501

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
    def LAST_ACK(self):
        pass

    @ATMT.state(final=1)
    def CLOSED(self):
        pass

    @ATMT.state(stop=1)
    def STOP(self):
        pass

    @ATMT.state()
    def STOP_SENT_FIN_ACK(self):
        pass

    @ATMT.condition(START)
    def connect(self):
        raise self.SYN_SENT()

    @ATMT.action(connect)
    def send_syn(self):
        self.l4[TCP].flags = "S"
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(SYN_SENT)
    def synack_received(self, pkt):
        if pkt[TCP].flags.SA:
            raise self.ESTABLISHED().action_parameters(pkt)

    @ATMT.action(synack_received)
    def send_ack_of_synack(self, pkt):
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.l4[TCP].flags = "A"
        self.send(self.l4)

    @ATMT.receive_condition(ESTABLISHED)
    def incoming_data_received(self, pkt):
        if not isinstance(pkt[TCP].payload, (NoPayload, conf.padding_layer)):
            raise self.ESTABLISHED().action_parameters(pkt)

    @ATMT.action(incoming_data_received)
    def receive_data(self, pkt):
        data = raw(pkt[TCP].payload)
        if data and self.l4[TCP].ack == pkt[TCP].seq:
            self.sack = self.l4[TCP].ack
            self.l4[TCP].ack += len(data)
            self.l4[TCP].flags = "A"
            # Answer with an Ack
            self.send(self.l4)
            # Process data - will be sent to the SuperSocket through this
            self.rcvbuf.on_packet_received(pkt)

    @ATMT.ioevent(ESTABLISHED, name="tcp", as_supersocket="tcplink")
    def outgoing_data_received(self, fd):
        raise self.ESTABLISHED().action_parameters(fd.recv())

    @ATMT.action(outgoing_data_received)
    def send_data(self, d):
        self.l4[TCP].flags = "PA"
        self.send(self.l4 / d)
        self.l4[TCP].seq += len(d)

    @ATMT.receive_condition(ESTABLISHED)
    def reset_received(self, pkt):
        if pkt[TCP].flags.R:
            raise self.CLOSED()

    @ATMT.receive_condition(ESTABLISHED)
    def fin_received(self, pkt):
        if pkt[TCP].flags.F:
            raise self.LAST_ACK().action_parameters(pkt)

    @ATMT.action(fin_received)
    def send_finack(self, pkt):
        self.l4[TCP].flags = "FA"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(LAST_ACK)
    def ack_of_fin_received(self, pkt):
        if pkt[TCP].flags.A:
            raise self.CLOSED()

    @ATMT.condition(STOP)
    def stop_requested(self):
        raise self.STOP_SENT_FIN_ACK()

    @ATMT.action(stop_requested)
    def stop_send_finack(self):
        self.l4[TCP].flags = "FA"
        self.send(self.l4)
        self.l4[TCP].seq += 1

    @ATMT.receive_condition(STOP_SENT_FIN_ACK)
    def stop_fin_received(self, pkt):
        if pkt[TCP].flags.F:
            raise self.CLOSED().action_parameters(pkt)

    @ATMT.action(stop_fin_received)
    def stop_send_ack(self, pkt):
        self.l4[TCP].flags = "A"
        self.l4[TCP].ack = pkt[TCP].seq + 1
        self.send(self.l4)

    @ATMT.timeout(SYN_SENT, 1)
    def syn_ack_timeout(self):
        raise self.CLOSED()

    @ATMT.timeout(STOP_SENT_FIN_ACK, 1)
    def stop_ack_timeout(self):
        raise self.CLOSED()
