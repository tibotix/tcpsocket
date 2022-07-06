from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler
import socket


class Server(ThreadingMixIn, TCPServer):
    allow_reuse_address = True


class Handler(BaseRequestHandler):
    def handle(self):
        print("connected")
        sock: socket.socket = self.request
        sock.settimeout(10)
        sock.send(b"Give me a string: ")
        s = sock.recv(1024)
        print(f"Got string: {s!s}")
        sock.send(b"You gave me " + s)


if __name__ == "__main__":
    with Server(("10.0.2.15", 1024), Handler) as server:
        print("Started")
        server.serve_forever()
