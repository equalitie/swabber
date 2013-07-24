#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import zmq
import random
from zmq.eventloop import ioloop, zmqstream

ioloop.install()

context   = zmq.Context(1)
socket    = context.socket(zmq.PUB)
publisher = zmqstream.ZMQStream(socket)
socket.bind("tcp://127.0.0.1:22620")

counter = 0 

def publish():
  #print "D:"
  global counter
  counter += 1
  ip_to_ban = "10.%d.%d.%d" % (int(random.random() * 255),
                               int(random.random() * 255),
                               int(random.random() * 255))
  publisher.send_multipart(("swabber_bans", ip_to_ban))

try:
  ioloop.PeriodicCallback(publish, 5).start()
  ioloop.IOLoop.instance().start()
except: 
  print "Banned %d times" % counter
