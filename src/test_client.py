# TCP RFC: https://datatracker.ietf.org/doc/html/rfc793


# from tcpsocket import TCPSocket
#
# s = TCPSocket("192.168.0.132", 1024, "10.0.2.15", 5467, verbose=1)
# s.connect()
# s.send(b"1\n")
# print(str(s.received_bytes))

from scapy.all import Raw
from tcp_client import TCP_client

s = TCP_client.tcplink(Raw, "192.168.0.132", 1024, sport=10000, debug=5)
print(str(s.recv()))
s.send(b"hello\n")
print(str(s.recv()))
s.recv()
# s.close()
