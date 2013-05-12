#!/usr/bin/env python2

#import iptables
import daemon

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

class BannedHost(Base):
    __tablename__ = 'banned'
    
    ipaddress = Column(String, primary_key=True)
    timeseen = Column(DateTime)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    
    def __init__(self, ipaddress, timeseen, firstseen, lastseen):
        self.ipaddress = ipaddress
        self.timeseen = timeseen
        self.firstseen = firstseen
        self.lastseen = lastseen
        
    def __repr__(self):
        return "<BannedHost('%s','%s', '%s', '%s')>" % (self.ipaddress, self.timeseen, 
                                                        self.firstseen, self.lastseen)

class BanEntry(Base): 
    __tablename__ = "bantable"

    banid = Column(Integer, autoincrement=True, primary_key=True)
    ipaddress = Column(String, ForeignKey("banned.ipaddress"))
    banstart = Column(DateTime)

    def __init__(self, ipaddress, banstart): 
        self.ipaddress = ipaddress
        self.banstart = banstart

    def __repr__(self):
        return "<BanEntry('%s', '%s')>" % (self.ipaddress, 
                                           self.banstart)

"""  banhistory(optionally used?):
   primary key: banID autoincrement
   foreign key: bannedhosts.ipaddress
   timestarted: datetime
   timefinished: datetime
"""

def main(): 
    engine = create_engine('sqlite:///:memory:', echo=True)
    Session = sessionmaker(bind=engine)

if __name__ == "__main__": 
    main()
