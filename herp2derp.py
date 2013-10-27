#!/usr/bin/env python

'''herp2derp
    github.com/nosmo/misc/herp2derp.py

 A crap tribute to fail2ban on a lower level.

  Useful for banning malicious attackers against services where
 long-lasting connection-occupying attacks are in use and you
 can't/don't want to/dont have time to limit connections or implement
 suitable firewall rules.

  Checks TCP socket connections over a time window. If the number of
 connections over the time window is greater than a threshold value,
 the IP address is banned, either using swabber's ban creation/expiry
 system or using iptables commands directly.

'''

import struct
import time
import socket
import collections
import commands

try:
    import zmq
except ImportError as e:
    pass

TIME_WINDOW = 60
CONN_THRESHOLD = 100
BAN_ENGINE = "echo"

hitcounter = collections.defaultdict(list)

myip = "10.0.0.1"

whitelist = [
    myip,
    "127.0.0.1",
    ]

def parse_line(section):
    interesting_part = section[:12]
    sl, local_address, rem_address, st, tx_queue, rx_queue, tr, tmwhen, retrnsmt, uid, timeout, inode = interesting_part

    local_address, local_port = local_address.split(":")
    local_address = socket.inet_ntoa(struct.pack("<L", int(local_address,16)))
    local_port = int(local_port, 16)
    rem_address, rem_port = rem_address.split(":")
    rem_address = socket.inet_ntoa(struct.pack("<L", int(rem_address,16)))
    rem_port = int(rem_port, 16)
    return rem_address, rem_port

def ban_echo(ip):
    ban_rule = "iptables -I INPUT -j DROP -s %s" % ip
    print ban_rule
    return True

def ban_iptables(ip):
    ban_rule = "iptables -I INPUT -j DROP -s %s" % ip
    status, output = commands.getstatusoutput(ban_rule)
    return True if not status else False

def ban_swabber(ip):
    if not zmq:
        raise SystemExit("swabber engine enabled but zmq not available!")

    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.connect("tcp://127.0.0.1:22620")
    socket.send_multipart(("swabber_bans", ip))
    socket.close()
    return True

banner = {"echo": ban_echo,
          "iptables": ban_iptables,
          "swabber": ban_swabber}
ban = banner[BAN_ENGINE]

def main():

    timetaken = 0

    while True:
        with open("/proc/net/tcp") as net_f:
            connectiondata = [ i.strip().split() for i in net_f.read().strip().split("\n") ]

            for section in connectiondata:
                if "local_address" in section:
                    # skip the header
                    continue

                rem_address, rem_port = parse_line(section)

                if rem_address == myip or rem_address in whitelist:
                    continue
                now = time.time()
                hitcounter[rem_address].append(now)

        if timetaken % 60 == 0:
            for ip, dates in hitcounter.iteritems():
                # filter out expired hits
                dates = [ date for date in dates if (time.time() - date) > TIME_WINDOW ]

            for ip, dates in hitcounter.iteritems():
                if len(dates) > CONN_THRESHOLD:
                    ban(ip)

            timetaken = 0

        timetaken += 1
        time.sleep(1)

if __name__ == "__main__":
    main()
