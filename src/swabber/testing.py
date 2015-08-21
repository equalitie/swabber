import unittest
import datetime
import commands
import threading
import os
import tempfile
from swabber import BanEntry
from swabber import BanCleaner
from swabber import BanFetcher

import zmq
from zmq.eventloop import ioloop, zmqstream

BAN_IP = "10.123.45.67"
BINDSTRING = "tcp://127.0.0.1:22620"
INTERFACE = "eth+"
BAN_METHOD = "iptables_cmd"

#Defining context outside to avoid attacker using up all FDs
context   = zmq.Context(1)

class Attacker(object): #(threading.Thread):

    def __init__(self, testip):
        self.testip = testip
        #threading.Thread.__init__(self)

    def start(self):
        socket    = context.socket(zmq.PUB)
        publisher = zmqstream.ZMQStream(socket)
        socket.connect(BINDSTRING)
        publisher.send_multipart(("swabber_bans", self.testip))
        publisher.close()
        socket.close(linger=0)
        #context.destroy(linger=0)
        return True

class StressTest(object):

    def __init__(self, testip, hit_times=500000):
        self.testip = testip
        self.hit_times = hit_times

    def run(self):

        bfetcher = BanFetcher(DB_CONN, BINDSTRING, False)
        bfetcher.start()

        print "Starting attacks"

        for i in range(self.hit_times):
            if i % 1000 == 0:
                print "Attacked %d times" % i

            a = Attacker(self.testip)
            a.start()
            del(a)

class Attacker(threading.Thread):
    def __init__(self, testip):
        self.testip = testip
        threading.Thread.__init__(self)

    def run(self):
        context   = zmq.Context(1)
        socket    = context.socket(zmq.PUB)
        publisher = zmqstream.ZMQStream(socket)
        socket.bind("tcp://127.0.0.1:22620")
        publisher.send_multipart(("swabber_bans", testip))
        return True

class StressTest(object):

    def __init__(self, testip, hit_times=1000000):
        self.testip = testip
        self.hit_times = hit_times

    def run(self):
        for i in range(self.hit_times):
            if i % 100 == 0:
                print "Attacked %d times" % i

            a = Attacker(self.testip)
            a.start()

class BanTests(unittest.TestCase):

    def testBan(self):
        ban = BanEntry(BAN_IP, datetime.datetime.now())
        ban.ban(INTERFACE)
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        ban.unban()
        self.assertIn(BAN_IP, output, msg="IP address not banned")
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="IP address was not unbanned")

    def test_whitelist(self):
        ban_fetcher = BanFester(BINDSTRING, INTERFACE,
                                BAN_METHOD, ["10.0.2.1"],
                                threading.Lock)
        self.assertFalse(ban_fetcher.subscription(("swabber_bans", "10.0.2.1"))

class CleanTests(unittest.TestCase):

    def testClean(self):

        ban_len = 1
        bantime = datetime.timedelta(minutes=(ban_len*2))
        ban = BanEntry(BAN_IP, datetime.datetime.now() - bantime)
        session.add(ban)
        session.commit()

        ban.ban(INTERFACE)
        cleaner = BanCleaner(db_conn, ban_len)
        cleaner.cleanBans()

        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="Ban was not reset by cleaner")

def main():
    if os.getuid() != 0:
        print "Tests must be run as root"
        raise SystemExit
    else:
        s = StressTest(BAN_IP)
        s.run()
        unittest.main()

if __name__ == '__main__':
    main()
