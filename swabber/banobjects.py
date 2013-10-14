#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import time
import commands
import hostsfile

class IPTablesCommandBanEntry(object):

    #good question
    #TODO
    fault_exception = Exception
   
    def __init__(self, ipaddress): 
        self.ipaddress = ipaddress
        self.banstart = None

        status, output = commands.getstatusoutput("/sbin/iptables -L -n")
        if status: 
            raise Exception("Couldn't list iptables rules!")

        droprules = filter(lambda a: a.startswith("DROP") and "swabber" in a, output.split("\n"))
        for rule in droprules: 
            action, proto, opt, src, dest, _, swabber, _ = droprules[0].split()
            if src == self.ipaddress:
                if ":" not in swabber: 
                    raise Exception("Malformed swabber rule in iptables! %s" % swabber)
                _, start = swabber.split(":")
                start = start.strip()
                self.banstart = int(start)
    
    def ban(self, interface=None): 
        interface_section = "-i %s" % interface if interface else ""

        now = int(time.time())
        command = "iptables -A INPUT -s %s %s -j DROP -m comment --comment \"swabber:%d\"" % (self.ipaddress, interface_section, now)
        status, output = commands.getstatusoutput(command)
        if status: 
            raise Exception("Couldn't set iptables rule for %s (command %s): %s" % (self.ipaddress, command, output))
        return True

    def unban(self): 
        command = "iptables -D INPUT -s %s -j DROP -m comment --comment \"swabber%d\"" % (self.ipaddress, self.banstart)
        status, output = commands.getstatusoutput(command)
        if status:
            raise Exception("failed to unban IP %s: %s" % (self.ipaddress, output))
        return True

    def __repr__(self):
        return "<BanEntry('%s', %s)>" % (self.ipaddress, 
                                         self.banstart)

class HostsBanEntry(object): 
    
    fault_exception = IOError

    def __init__(self, ipaddress): 
        self.hostsfile = hostsfile.HostsDeny()
        self.ipaddress = ipaddress
        self.banstart = None
        if ipaddress in self.hostsfile: 
            hostsfileentry = self.hostsfile[ipaddress]
            if hostsfileentry[2] and "swabber" in hostsfileentry[2]:
                self.banstart = int(hostsfileentry[2].split(":")[1])

    def ban(self, interface=None): 
        #interface is a dummy 
        self.banstart = int(time.time())
        comment = "swabber:%s" % self.banstart
        self.hostsfile.add(self.ipaddress, comment=comment)

        return True

    def unban(self): 
        self.hostsfile -= self.ipaddress

    def __repr__(self):
        return "<BanEntry('%s', %s)>" % (self.ipaddress, 
                                         self.banstart)

class IPTCBanEntry(object): 

    fault_exception = iptc.IPTCError

    def __init__(self, ipaddress): 
        self.ipaddress = ipaddress

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        self.rule = None
        self.banstart = None

        rules = chain.rules
        for rule in rules:
            if rule.src == "%s/255.255.255.255" % self.ipaddress:
                if rule.matches:
                    comment = rule.matches[0].comment
                    #TODO regexp matching
                    if "swabber:" in comment: 
                        self.chain = chain
                        self.rule = rule
                        self.banstart = int(comment.split(":")[1].strip('"'))

        #if not self.rule and not self.banstart:
        #    # We're a new rule
        #    self.banstart = int(time.time())

        if not self.rule: 
            self.table = None
            self.chain = None

    #TODO
    #@staticmethod
    #def _static_ban(ban, interface): 

    def ban(self, interface): 
        self.banstart = int(time.time())

        self.table = iptc.Table(iptc.Table.FILTER)
        self.chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        rule = iptc.Rule()
        rule.in_interface = interface
        rule.src = self.ipaddress
        target = iptc.Target(rule, "DROP")
        rule.target = target

        rulecomment = rule.create_match("comment")
        rulecomment.comment = "swabber:%s" % self.banstart

        self.rule = rule

        self.chain.insert_rule(rule)

        return True

    def unban(self): 
        if not self.rule:
            return False
        self.chain.delete_rule(self.rule)
        return True

    def __repr__(self):
        return "<BanEntry('%s', %s)>" % (self.ipaddress, 
                                         self.banstart)

entries = {
    "iptables_cmd": IPTablesCommandBanEntry,
    "iptables": IPTCBanEntry, 
    "hostsfile": HostsBanEntry
    }

BanEntry = HostsBanEntry

def main(): 
    pass

if __name__ == "__main__": 
    main()
