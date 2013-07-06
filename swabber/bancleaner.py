#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import time
import daemon
import logging
import banobjects
import threading
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

"""Clean rules that have expired"""

#TODO make me  options
#DB_CONN = 'mysql://root@127.0.0.1/swabber'
DB_CONN = 'sqlite:///swabber.db'
#minutes
BANTIME = 2

class BanCleaner(threading.Thread):

    def __init__(self, db_uri, bantime): 
        self.db_uri = db_uri
        self.bantime = bantime
        engine = create_engine(db_uri, echo=True)
        self.Sessionmaker = sessionmaker(bind=engine)
        self.timelimit = datetime.timedelta(minutes=bantime)

        self.running = False

    def cleanBans(self):
        session = self.Sessionmaker()

        ban_entries = session.query(banobjects.BanEntry).all()
        for ban in ban_entries:
            if datetime.datetime.now() - ban.banstart > self.timelimit:
                logging.info("Unbanning %s as the ban has expired", ban.ipaddress)
                ban.unban()
                session.delete(ban)
        session.commit()
        return True

    def run(self): 
        self.running = True
        while self.running:
            try:
                self.cleanBans()
                time.sleep(0.1)
            except Exception as e: 
                logging.error("Uncaught exception in cleaner! %s", str(e))
                self.running = False

        return False

def main():
    b = BanCleaner(DB_CONN)
    b.run()

if __name__ == "__main__": 
    main()
