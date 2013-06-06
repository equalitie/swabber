import json
import datetime
import zmq
import sys
import logging
from zmq.eventloop import ioloop, zmqstream

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import banobjects

#TODO make me an option
DB_CONN = 'sqlite:///:memory:'

def main(verbose=False): 

    context = zmq.Context()
    socket = context.socket (zmq.SUB)
    subscriber = zmqstream.ZMQStream(socket)
    socket.setsockopt(zmq.SUBSCRIBE, "swabber_bans")
    socket.connect("tcp://127.0.0.1:22620")

    engine = create_engine(DB_CONN, echo=verbose)
    Session = sessionmaker(bind=engine)
    banobjects.Base.metadata.create_all(engine)
 
    def subscription(message):
        session = Session()
        action, ipaddress = message
        if action == "swabber_bans": 
            logging.debug("Received ban for %s", message[1])
            thenow = datetime.datetime.now()

            banned_host = session.query(banobjects.BannedHost).filter_by(ipaddress=ipaddress).first()
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
                print session.query(banobjects.BanEntry).all()
                ban_entry = banobjects.BanEntry(ipaddress, thenow) 
                logging.info("Created ban for %s at %s. %s", ban_entry.ipaddress,
                             thenow, 
                             " Host has been seen %d times before." % banned_host.timesbanned if \
                                 banned_host.timesbanned else "")
                try:
                    ban_entry.ban()
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
            print message
        
    subscriber.on_recv(subscription)
    ioloop.IOLoop.instance().start()

if __name__ == "__main__": 

    verbose = False

    mainlogger = logging.getLogger()

    logging.basicConfig(level=logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    mainlogger.addHandler(ch)

    main(verbose)
                      
