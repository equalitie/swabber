#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import daemon
import iptc
import hostsfile

import banobjects

import time
import logging
import threading
import traceback
import datetime
import sys

"""Clean rules that have expired"""

#minutes
BANTIME = 2

BANLIMIT = 10

class BanCleaner(threading.Thread):

    def _iptc_cleanBans(self, interface=None):

        banlist = []

        with self.iptables_lock:
            table = iptc.Table(iptc.Table.FILTER, autocommit=False)
            chain = iptc.Chain(table, "INPUT")
            rules = chain.rules
            for index, rule in enumerate(rules):
                # This does two selects
                # dumb but fix later.

                now = int(time.time())
                ban = self.BanObject(rule.src.split("/")[0])
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

    def _hosts_cleanBans(self, interface=None):

        hostsban = hostsfile.HostsDeny()
        for banentry in hostsban:
            ban = self.BanObject(banentry[1])
            if not ban.banstart:
                continue

            now = int(time.time())
            if (now - ban.banstart) > self.timelimit:
                logging.info("Unbanning %s as the ban has expired", ban.ipaddress)
                ban.unban()

    def _iptables_cmd_cleanBans(self, interface=None):
        for rule in banobjects.IPTablesCommandBanEntry.list(self.timelimit):
            ruletodelete = banobjects.IPTablesCommandBanEntry(rule)
            ruletodelete.unban(interface)

    #TODO make lock optional
    def __init__(self, bantime, backend, lock, interface):
        self.bantime = bantime
        self.interface = interface
        self.BanObject = banobjects.entries[backend]
        self.timelimit = bantime * 60
        threading.Thread.__init__(self)
        self.running = False

        self.iptables_lock = lock

        self.cleanBans = {
            "hostsfile": self._hosts_cleanBans,
            "iptables": self._iptc_cleanBans,
            "iptables_cmd": self._iptables_cmd_cleanBans
            }[backend]

    def stopIt(self):
        self.running = False

    def run(self):
        self.running = True
        logging.info("Started running bancleaner")
        while self.running:
            try:
                self.cleanBans(self.interface)
                time.sleep(60)
            except Exception as e: 
                logging.error("Uncaught exception in cleaner! %s", str(e))
                traceback.print_exc()
                #self.running = False

        return False

def main():

    mainlogger = logging.getLogger()

    #logging.basicConfig(level=logging.DEBUG)
    #ch = logging.StreamHandler(sys.stdout)
    #ch.setLevel(logging.DEBUG)
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #ch.setFormatter(formatter)
    #mainlogger.addHandler(ch)

    b = BanCleaner(BANTIME, "iptables", threading.Lock())
    b.run()

if __name__ == "__main__":
    main()
