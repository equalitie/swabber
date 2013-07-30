#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import json
import iptc
import zmq

import datetime
import logging
import re
import sys
import threading

from zmq.eventloop import ioloop, zmqstream

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import banobjects

#TODO make me an option
#DB_CONN = 'mysql://root@127.0.0.1/swabber'
DB_CONN = 'sqlite:////tmp/swabber.db'
BINDSTRING = "tcp://127.0.0.1:22620"

class BanFetcher(threading.Thread):

    def subscription(self, message):
        session = self.Sessionmaker()
        action, ipaddress = message

        ipaddress= ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting", ipaddress)
            return False

        if action == "swabber_bans":

            logging.debug("Received ban for %s", message[1])
            thenow = datetime.datetime.now()

            try:
                banned_host = session.query(banobjects.BannedHost).filter_by(ipaddress=ipaddress).first()
            except Exception as e:
                # sorry for the pokemon
                #TODO catch more gracefully
                loggging.error("Failed to select host for %s - bad address?", ipaddress)
                return False

            if not banned_host:
                banned_host = banobjects.BannedHost(ipaddress, thenow, thenow)
                logging.info("Created ban for %s at %s", ipaddress, thenow)
            else:
                timebefore = banned_host.lastseen
                banned_host.timesbanned += 1
                banned_host.lastseen = thenow
                logging.info("Changed lastseen for %s from %s to %s", ipaddress,
                             timebefore, thenow)

            ban_entry = session.query(banobjects.BanEntry).filter_by(ipaddress=ipaddress).first()
            if not ban_entry:
                ban_entry = banobjects.BanEntry(ipaddress, thenow)
                logging.info("Created ban for %s at %s. %s", ban_entry.ipaddress,
                             thenow,
                             " Host has been seen %d times before." % banned_host.timesbanned if \
                                 banned_host.timesbanned else "")
                try:
                    with self.iptables_lock:
                        from time import sleep
                        logging.debug("Fetcher is locking and sleeping");
                        sleep(5);
                        logging.debug("Fetcher woke up");
                        logging.debug("About to ban %s on %s", ipaddress, self.interface)
                        import pdb
                        pdb.set_trace()
                        ban_entry.ban(self.interface)
                        logging.debug("Successfully banned %s", ipaddress)
                except iptc.IPTCError as e:
                    logging.error("Failed to initialise ban - do we lack permissions?: %s", e)
                    raise SystemExit

            else:

                timediff = thenow - ban_entry.banstart
                ban_entry.banstart = thenow
                logging.info("Extended ban for %s by %s.", ban_entry.ipaddress,
                             timediff)

            session.add(ban_entry)
            session.add(banned_host)
            session.commit()
        else:
            logging.error("Got an invalid message header: %s", message)


    def __init__(self, db_conn, bindstring,
                 interface, lock,
                 verbose=False):
        self.bindstring = bindstring
        self.interface = interface

        context = zmq.Context()
        self.socket = context.socket (zmq.SUB)
        subscriber = zmqstream.ZMQStream(self.socket)
        self.socket.setsockopt(zmq.SUBSCRIBE, "swabber_bans")
        self.socket.connect(bindstring)

        engine = create_engine(db_conn, echo=verbose)
        self.Sessionmaker = sessionmaker(bind=engine)

        self.iptables_lock = lock

        threading.Thread.__init__(self)

        subscriber.on_recv(self.subscription)

    def stopIt(self):
        self.loop.stop()

    def run(self):
        self.loop = ioloop.IOLoop.instance().start()

if __name__ == "__main__":

    verbose = True

    mainlogger = logging.getLogger()

    banobjects.createDB(DB_CONN)
    logging.basicConfig(level=logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    mainlogger.addHandler(ch)

    bfetcher = BanFetcher(DB_CONN, BINDSTRING, verbose)
    bfetcher.run()
