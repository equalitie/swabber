#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import time
import hostsfile

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

entries={
    "iptables": IPTCBanEntry, 
    "hostsfile": HostsBanEntry
    }

BanEntry=HostsBanEntry

def main(): 
    pass

if __name__ == "__main__": 
    main()
