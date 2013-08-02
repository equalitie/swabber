#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import time

class BanEntry(object): 

    def __init__(self, ipaddress): 
        self.ipaddress = ipaddress

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        self.rule = None
        self.banstart = None

        for rule in chain.rules:
            if rule.src == "%s/255.255.255.255" % self.ipaddress:
                if rule.matches:
                    comment = rule.matches[0].comment
                    #TODO regexp matching
                    if "swabber:" in comment: 
                        self.rule = rule
                        self.banstart = int(comment.split(":")[1].strip('"'))

        #if not self.rule and not self.banstart:
        #    # We're a new rule
        #    self.banstart = int(time.time())

        self.table = None
        self.chain = None

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

    def __del__(self): 
        del(self.table)
        del(self.chain)
        del(self.rule)

    def unban(self): 
        if not self.rule: 
            return False
        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.delete_rule(self.rule)
        return True

    def __repr__(self):
        return "<BanEntry('%s', %s)>" % (self.ipaddress, 
                                         self.banstart)

def main(): 
    pass

if __name__ == "__main__": 
    main()
