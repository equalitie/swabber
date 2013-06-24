import unittest
import datetime
import commands
import os
import tempfile
from banobjects import BanEntry, createDB
from bancleaner import BanCleaner
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


BAN_IP = "10.123.45.67"

class BanTests(unittest.TestCase):

    def testBan(self):
        ban = BanEntry(BAN_IP, datetime.datetime.now())
        ban.ban()
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        ban.unban()
        self.assertIn(BAN_IP, output, msg="IP address not banned")
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="IP address was not unbanned")

class CleanTests(unittest.TestCase): 
    
    def testClean(self): 
        db_conn = 'sqlite:///%s/swabber.db' % tempfile.mkdtemp()
        createDB(db_conn)

        engine = create_engine(db_conn, echo=False)
        Sessionmaker = sessionmaker(bind=engine)
        session = Sessionmaker()

        ban_len = 1
        bantime = datetime.timedelta(minutes=(ban_len*2))
        ban = BanEntry(BAN_IP, datetime.datetime.now() - bantime)
        session.add(ban)
        session.commit()

        ban.ban()
        cleaner = BanCleaner(db_conn, ban_len)
        cleaner.cleanBans()
        
        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        self.assertNotIn(BAN_IP, output, msg="Ban was not reset by cleaner")

def main():
    if os.getuid() != 0: 
        print "Tests must be run as root"
        raise SystemExit
    else:
        unittest.main()

if __name__ == '__main__':
    main()

