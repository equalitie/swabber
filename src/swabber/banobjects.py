#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import daemon

from sqlalchemy import Column, Integer, String, \
    DateTime, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

#TODO config option
# eth+ bans all eth* interfaces
BAN_INTERFACE = "eth+"
#TODO make me an option
DB_CONN = 'sqlite:///:memory:'

class BannedHost(Base):
    __tablename__ = 'banned'
    
    ipaddress = Column(String, primary_key=True)
    firstseen = Column(DateTime)
    lastseen = Column(DateTime)
    timesbanned = Column(Integer)
    
    def __init__(self, ipaddress, firstseen, lastseen):
        self.ipaddress = ipaddress
        self.firstseen = firstseen
        self.lastseen = lastseen
        #TODO use this as a threshold for forcing permabans
        self.timesbanned = 0 

        print "Created %s" % ipaddress
        
    def __repr__(self):
        return "<BannedHost('%s','%s', '%s')>" % (self.ipaddress, 
                                                  self.firstseen, 
                                                  self.lastseen)

class BanEntry(Base): 
    __tablename__ = "bantable"

    banid = Column(Integer, autoincrement=True, primary_key=True)
    ipaddress = Column(String, ForeignKey("banned.ipaddress"))
    banstart = Column(DateTime)

    def __init__(self, ipaddress, banstart): 
        self.ipaddress = ipaddress
        self.banstart = banstart

    def ban(self): 
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        rule = iptc.Rule()
        rule.in_interface = BAN_INTERFACE
        rule.src = self.ipaddress
        target = iptc.Target(rule, "DROP")
        rule.target = target
        chain.insert_rule(rule)

        return True

    def unban(self): 
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        for rule in chain.rules:
            if rule.src == "%s/255.255.255.255" % self.ipaddress:
                chain.delete_rule(rule)
                return True
        return False

    def __repr__(self):
        return "<BanEntry('%s', '%s')>" % (self.ipaddress, 
                                           self.banstart)

"""  banhistory(optionally used?):
   primary key: banID autoincrement
   foreign key: bannedhosts.ipaddress
   timestarted: datetime
   timefinished: datetime
"""

def createDB(db_conn=DB_CONN):
    engine = create_engine(db_conn, echo=True)
    Base.metadata.create_all(engine)

def main(): 
    createDB()

if __name__ == "__main__": 
    main()
