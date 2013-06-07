#!/usr/bin/env python2

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

    def __init__(self, db_uri): 
        self.db_uri = db_uri
        engine = create_engine(db_uri, echo=True)
        self.Sessionmaker = sessionmaker(bind=engine)
        self.timelimit = datetime.timedelta(minutes=BANTIME)

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

def main():
    b = BanCleaner(DB_CONN)
    b.cleanBans()

if __name__ == "__main__": 
    main()
