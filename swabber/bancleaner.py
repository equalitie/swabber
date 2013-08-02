#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import daemon
import iptc

from banobjects import BanEntry

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

    def __init__(self, bantime, lock): 
        self.bantime = bantime
        self.timelimit = bantime * 60
        threading.Thread.__init__(self)
        self.running = False

        self.iptables_lock = lock

    def cleanBans(self):
        
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

        for rule in chain.rules: 
            print "Passing over chain"
            # This does two selects 
            # dumb but fix later. 

            now = int(time.time())
            ban = BanEntry(rule.src.split("/")[0])
            if not ban.rule: 
                continue

            if (now - ban.banstart) > self.timelimit: 
                logging.info("Unbanning %s as the ban has expired", ban.ipaddress)
                with self.iptables_lock: 
                    ban.unban()
                logging.debug("Unbanned %s", ban.ipaddress)

            del(ban)
        del(table)
        del(chain)

        return True
        
    def stopIt(self):
        self.running = False

    def run(self): 
        self.running = True
        logging.info("Started running bancleaner")
        while self.running:
            try:
                self.cleanBans()
                time.sleep(5)
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

    b = BanCleaner(BANTIME, threading.Lock())
    b.run()

if __name__ == "__main__": 
    main()
