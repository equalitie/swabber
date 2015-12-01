#!/usr/bin/env python 

import unittest
import commands
import threading
import os
import time

from banobjects import IPTablesCommandBanEntry
from bancleaner import BanCleaner
from banfetcher import BanFetcher

BAN_IP = "10.123.45.67"
BINDSTRING = ["tcp://127.0.0.1:22620"]
INTERFACE = "eth+"
BAN_BACKEND = "iptables_cmd"

class IPTablesCommandBanTests(unittest.TestCase):

    ''' Tests for the IPTables command-based ban objects.
    '''

    def test_ban(self):
        ''' Create a ban and remove it. '''

        ban = IPTablesCommandBanEntry(BAN_IP)
        ban.ban(interface=INTERFACE)

        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertEqual(status, 0, 
                         msg="Failed to run iptables command: %s" % output)
        self.assertIn(BAN_IP, output, msg="IP address not banned")
        ban.unban(interface=INTERFACE)
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="IP address was not unbanned")

    def test_whitelist_ip(self):
        ''' Test the whitelisting of a single IP ''' 
        
        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)
        # An address that shouldn't be banned
        self.assertFalse(
            ban_fetcher.subscription(("swabber_bans", "10.0.220.1")), 
            msg="IP that should have been whitelisted was banned!")

    def test_whitelist_network(self): 
        ''' Test the whitelisting of a whole network '''

        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)
        # An address in a network that shouldn't be banned
        self.assertFalse(
            ban_fetcher.subscription(("swabber_bans", "10.0.222.3")), 
            msg="IP in a network that should have been whitelisted was banned!")

    def test_whitelist_notwhitelisted(self): 
        ''' Test the unwhitelisting of an IP to ensure it isn't whitelisted '''

        lock = threading.Lock()
        ban_fetcher = BanFetcher(BINDSTRING, INTERFACE,
                                 BAN_BACKEND, ["10.0.220.1", "10.0.222.1/24"],
                                 lock)

        # An address that should be banned
        self.assertTrue(
            ban_fetcher.subscription(("swabber_bans", "10.0.220.2")), 
            msg="Unwhitelisted IP was whitelisted")

        # clean up after ourselves
        ban = IPTablesCommandBanEntry("10.0.220.2")
        ban.unban(interface=INTERFACE)

class CleanTests(unittest.TestCase):

    ''' Test the bancleaner object '''

    def test_clean(self):
        ''' Test the cleaning of bans after a very short time window '''

        ban_len = 1
        ban = IPTablesCommandBanEntry(BAN_IP)
        ban.ban(INTERFACE)
        time.sleep(ban_len*2)

        cleaner = BanCleaner(ban_len, BAN_BACKEND, threading.Lock(), INTERFACE)
        cleaner.clean_bans(INTERFACE)

        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertEqual(status, 0, 
                         msg="Failed to run iptables command: %s" % output)
        self.assertNotIn(BAN_IP, output, msg="Ban was not reset by cleaner")

def main():
    ''' Run some tests boyo '''

    if os.getuid() != 0:
        print "Tests must be run as root"
        raise SystemExit
    else:
        unittest.main()

if __name__ == '__main__':
    main()
