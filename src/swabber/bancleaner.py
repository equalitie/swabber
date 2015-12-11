#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import hostsfile

import banobjects

import time
import logging
import threading
import traceback

# Clean rules that have expired

# in minutes
BANTIME = 2

BANLIMIT = 10

class BanCleaner(object):

    def _iptc_clean_bans(self, interface=None):

        banlist = []

        with self.iptables_lock:
            table = iptc.Table(iptc.Table.FILTER, autocommit=False)
            chain = iptc.Chain(table, "INPUT")
            rules = chain.rules
            for index, rule in enumerate(rules):
                # This does two selects
                # dumb but fix later.

                now = int(time.time())
                ban = self.ban_object(rule.src.split("/")[0])
                if not ban.banstart:
                    continue

                if (now - ban.banstart) > self.timelimit:
                    logging.info("Unbanning %s as the ban has expired", ban.ipaddress)
                    banlist.append(ban)
                    logging.debug("Unbanned %s", ban.ipaddress)
                if index > BANLIMIT:
                    # Rate limit a little
                    break

            for ban in banlist:
                ban.unban()
            table.commit()

        return True

    def _hosts_clean_bans(self, interface=None):

        hostsban = hostsfile.HostsDeny()
        for banentry in hostsban:
            ban = self.ban_object(banentry[1])
            if not ban.banstart:
                continue

            now = int(time.time())
            if (now - ban.banstart) > self.timelimit:
                logging.info("Unbanning %s as the ban has expired", ban.ipaddress)
                ban.unban()

    def _iptables_cmd_clean_bans(self, interface=None):
        for rule in banobjects.IPTablesCommandBanEntry.list(self.timelimit):
            ruletodelete = banobjects.IPTablesCommandBanEntry(rule)
            logging.info("Unbanning %s as the ban has expired", ruletodelete.ipaddress)
            with self.iptables_lock:
                ruletodelete.unban(interface)

    def __init__(self, bantime, backend, lock, interface):
        self.bantime = bantime
        self.interface = interface
        self.ban_object = banobjects.entries[backend]
        self.timelimit = bantime

        self.iptables_lock = lock

        self.clean_bans = {
            "hostsfile": self._hosts_clean_bans,
            "iptables": self._iptc_clean_bans,
            "iptables_cmd": self._iptables_cmd_clean_bans
            }[backend]

def main():

    #mainlogger = logging.getLogger()
    #logging.basicConfig(level=logging.DEBUG)
    #ch = logging.StreamHandler(sys.stdout)
    #ch.setLevel(logging.DEBUG)
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #ch.setFormatter(formatter)
    #mainlogger.addHandler(ch)

    b = BanCleaner(BANTIME, "iptables", threading.Lock(), "eth+")
    while True:
        b.clean_bans()
        time.sleep(60)

if __name__ == "__main__":
    main()
