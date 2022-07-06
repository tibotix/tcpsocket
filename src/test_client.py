from tcpsocket import TCPSocket


s = TCPSocket("10.0.2.15", 1024, "10.0.2.15", 5467, verbose=1)
s.connect()
s.send(b"1\n")
print(str(s.received_bytes))
