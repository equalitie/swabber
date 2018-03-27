#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import zmq
import ipaddr
from zmq.eventloop import ioloop, zmqstream

import datetime
import logging
import re
import sys
import threading

import banobjects

BIND_STRINGS = ["tcp://127.0.0.1:22620"]

class BanFetcher(threading.Thread):

    #TODO make lock optional
    def __init__(self, bindstrings,
                 interface, backend,
                 whitelist, lock):
        self.bindstrings = bindstrings
        self.interface = interface
        self.backend = backend
        self.ban_object = banobjects.entries[backend]

        self.whitelist = {"networks": [], "addresses": []}
        for entry in whitelist:
            if "/" in entry:
                # This check sucks but it'll do for now. ipaddr will
                # throw a suitable exception if this doesn't work
                self.whitelist["networks"].append(ipaddr.IPNetwork(entry))
            else:
                self.whitelist["addresses"].append(ipaddr.IPAddress(entry))

        self.sockets = {}

        for bindstring in bindstrings:

            context = zmq.Context()
            self.sockets[bindstring] = context.socket(zmq.SUB)
            subscriber = zmqstream.ZMQStream(self.sockets[bindstring])

            if hasattr(zmq, "RCVHWM"):
                self.sockets[bindstring].setsockopt(zmq.RCVHWM, 2000)
            if hasattr(zmq, "SNDHWM"):
                self.sockets[bindstring].setsockopt(zmq.SNDHWM, 2000)
            if hasattr(zmq, "HWM"):
                self.sockets[bindstring].setsockopt(zmq.HWM, 2000)

            # SWAP is removed in zmq :(
            if hasattr(zmq, "SWAP"):
                self.sockets[bindstring].setsockopt(zmq.SWAP, 200*2**10)

            self.sockets[bindstring].setsockopt(zmq.SUBSCRIBE, "swabber_bans")
            self.sockets[bindstring].connect(bindstring)
            subscriber.on_recv(self.subscription)

        self.iptables_lock = lock

        threading.Thread.__init__(self)
        self.daemon = True

    def subscription(self, message):
        if len(message) != 2:
            logging.debug("ZMQ received invalid message: %s", message)
            return False

        action, ipaddress = message

        ipaddress = ipaddress.strip()
        ipmatch = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if not ipmatch.match(ipaddress):
            logging.error("Failed to validate IP address %s - rejecting", ipaddress)
            return False

        ipaddr_obj = ipaddr.IPAddress(ipaddress)
        for network in self.whitelist["networks"]:
            if ipaddr_obj in network:
                logging.info("Not banning IP %s because it is in whitelisted network %s",
                             ipaddress, str(network))
                return False
        for whitelist_ip in self.whitelist["addresses"]:
            if ipaddr_obj == whitelist_ip:
                logging.info("Not banning IP %s because it is whitelisted", ipaddress)
                return False

        if action == "swabber_bans":
            logging.debug("Received ban for %s", message[1])
            thenow = datetime.datetime.now()

            with self.iptables_lock:
                ban = self.ban_object(ipaddress)
                logging.debug("Created banentry for %s", ipaddress)

                logging.debug("Fetcher got iptables lock")
                try:
                    if ban.new_ban:
                        logging.info("Created ban for %s", ipaddress)
                        ban.ban(self.interface)
                    else:
                        oldstart = ban.banstart
                        ban.unban(self.interface)
                        ban.ban(self.interface)
                        newstart = ban.banstart
                        logging.info("Extended ban for %s from %d to %d", ipaddress,
                                     oldstart, newstart)

                except self.ban_object.fault_exception as e:
                    logging.error("Failed to initialise ban - do we lack permissions?: %s", e)

        else:
            logging.error("Got an invalid message header: %s", message)
            return False
        return True

    def stop_running(self):
        self.loop.stop()

    def run(self):
        self.loop = ioloop.IOLoop.instance()
        self.loop.start()

def main():
    verbose = False

    if verbose:
        mainlogger = logging.getLogger()

        logging.basicConfig(level=logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        mainlogger.addHandler(ch)

    bfetcher = BanFetcher(BIND_STRINGS[0], "eth+", "iptables", threading.Lock())
    bfetcher.run()

if __name__ == "__main__":

    main()
