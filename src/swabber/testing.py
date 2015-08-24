#!/usr/bin/env python 

import unittest
import datetime
import commands
import threading
import os
import time
import tempfile

from banobjects import IPTablesCommandBanEntry
from bancleaner import BanCleaner
from banfetcher import BanFetcher

import zmq
from zmq.eventloop import ioloop, zmqstream

BAN_IP = "10.123.45.67"
BINDSTRING = ["tcp://127.0.0.1:22620"]
INTERFACE = "eth+"
BAN_BACKEND = "iptables_cmd"

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

class IPTablesCommandBanTests(unittest.TestCase):

    def test_ban(self):
        ban = IPTablesCommandBanEntry(BAN_IP)
        ban.ban(interface=INTERFACE)
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")

        self.assertIn(BAN_IP, output, msg="IP address not banned")
        ban.unban(interface=INTERFACE)
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="IP address was not unbanned")

    def test_whitelist_ip(self):
        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)
        # An address that shouldn't be banned
        self.assertFalse(ban_fetcher.subscription(("swabber_bans", "10.0.220.1")), 
                         msg="IP that should have been whitelisted was banned!")

    def test_whitelist_network(self): 
        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)
        # An address in a network that shouldn't be banned
        self.assertFalse(ban_fetcher.subscription(("swabber_bans", "10.0.222.3")), 
                         msg="IP in a network that should have been whitelisted was banned!")

    def test_whitelist_notwhitelisted(self): 
        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)

        # An address that should be banned
        self.assertTrue(ban_fetcher.subscription(("swabber_bans", "10.0.220.2")), 
                        msg="IP that should not have been whitelisted was not banned")

        # clean up after ourselves
        ban = IPTablesCommandBanEntry("10.0.220.2")
        ban.unban(interface=INTERFACE)

class CleanTests(unittest.TestCase):

    def testClean(self):

        ban_len = 1
        bantime = datetime.timedelta(minutes=(ban_len*2))
        ban = IPTablesCommandBanEntry(BAN_IP)
        ban.ban(INTERFACE)
        time.sleep(ban_len*2)

        cleaner = BanCleaner(ban_len, BAN_BACKEND, threading.Lock(), INTERFACE)
        cleaner.clean_bans(INTERFACE)

        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="Ban was not reset by cleaner")

def main():
    if os.getuid() != 0:
        print "Tests must be run as root"
        raise SystemExit
    else:
        #s = StressTest(BAN_IP)
        #s.run()
        unittest.main()

if __name__ == '__main__':
    main()
