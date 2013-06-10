import zmq
from zmq.eventloop import ioloop, zmqstream

ioloop.install()

context   = zmq.Context(1)
socket    = context.socket(zmq.PUB)
publisher = zmqstream.ZMQStream(socket)
socket.bind("tcp://127.0.0.1:22620")

def publish():
  print "D:"
  publisher.send_multipart(("swabber_bans", "72.166.186.151"))

ioloop.PeriodicCallback(publish, 5000).start()
ioloop.IOLoop.instance().start()
