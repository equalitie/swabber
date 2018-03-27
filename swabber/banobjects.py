#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

import iptc
import time
import commands
import logging
import hostsfile

def get_iptables_version():
    status, output = commands.getstatusoutput('/sbin/iptables --version')
    if status != 0:
        return None
    version = output.strip().split(" ")[1]
    if version.startswith("v"):
        version = version[1:]
    return [ int(i) for i in version.split(".") ]

IPTABLES_VERSION = get_iptables_version()

def iptables_has_wait():
    introduced_in = [1, 4, 20]
    if not IPTABLES_VERSION:
        return False
    if IPTABLES_VERSION[0] > introduced_in[0]:
        return True
    elif IPTABLES_VERSION[1] > introduced_in[1]:
        return True
    elif IPTABLES_VERSION[2] >= introduced_in[2]:
        return True
    else:
        return False

class IPTablesCommandBanEntry(object):

    fault_exception = Exception

    def __init__(self, ipaddress):
        self.ipaddress = ipaddress
        self.banstart = None

        self.new_ban = True

        for rule, start in self.list().iteritems():
            if rule == self.ipaddress:
                self.banstart = int(start)
                self.new_ban = False

    @staticmethod
    def list(timelimit=None, wait=True):
        # timelimit - limit the listing to entries in the list
        # $timelimit seconds

        # wait - use the iptables wait to get a lock for listing. Will
        # slow down some operations, but means they will definitely
        # happen. Has no effect if iptables doesn't support it.

        iptables_command = "/sbin/iptables -L -n"
        if wait and iptables_has_wait():
            iptables_command += " -w"

        rulesdict = {}
        status, output = commands.getstatusoutput(iptables_command)
        if status:
            # This usually indicates that there's an xtables lock
            logging.error("Couldn't list iptables rules! %s", output)
            return rulesdict

        droprules = [ i for i in output.split("\n") if i.startswith("DROP") and "swabber" in i ]
        for rule in droprules:
            action, proto, opt, src, dest, _, swabber, _ = rule.split()
            if ":" not in swabber:
                raise Exception("Malformed swabber rule in iptables! %s" % swabber)
            _, start = swabber.split(":")
            start = int(start.strip())
            if not timelimit or (timelimit and (time.time() - start > timelimit)):
                rulesdict[src] = start

        return rulesdict

    def ban(self, interface=None, wait=True):
        interface_section = "-i %s" % interface if interface else ""

        now = int(time.time())
        iptables_command = ("iptables -I INPUT -s %s %s -j DROP -m comment"
                   " --comment \"swabber:%d\"") % (
                       self.ipaddress, interface_section, now)

        if wait and iptables_has_wait():
            iptables_command += " -w"

        status, output = commands.getstatusoutput(iptables_command)
        self.banstart = now

        if status:
            raise Exception("Couldn't set iptables rule for %s (command %s): %s" % (
                self.ipaddress, command, output))
        return True

    def unban(self, interface=None, wait=True):
        interface_section = "-i %s" % interface if interface else ""

        iptables_command = "iptables -D INPUT -s %s -j DROP -m comment --comment \"swabber:%d\" %s" % (self.ipaddress, self.banstart, interface_section)
        if wait and iptables_has_wait():
            iptables_command += " -w"

        status, output = commands.getstatusoutput(iptables_command)
        if status:
            raise Exception("failed to unban IP %s: %s command %s" % (self.ipaddress, output, iptables_command))
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
        self.new_ban = True
        if ipaddress in self.hostsfile:
            hostsfileentry = self.hostsfile[ipaddress]
            if hostsfileentry[2] and "swabber" in hostsfileentry[2]:
                self.banstart = int(hostsfileentry[2].split(":")[1])
                self.new_ban = False

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

        table = iptc.Table(iptc.Table.FILTER, autocommit=False)
        chain = iptc.Chain(table, "INPUT")
        self.rule = None
        self.banstart = None
        self.new_ban = True

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
                        self.new_ban = False

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

        self.table = iptc.Table(iptc.Table.FILTER, autocommit=False)
        self.chain = iptc.Chain(table, "INPUT")
        rule = iptc.Rule()
        rule.in_interface = interface
        rule.src = self.ipaddress
        target = iptc.Target(rule, "DROP")
        rule.target = target

        rulecomment = rule.create_match("comment")
        rulecomment.comment = "swabber:%s" % self.banstart

        self.rule = rule

        self.chain.insert_rule(rule)
        self.table.commit()

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

BanEntry = IPTablesCommandBanEntry

def main():
    pass

if __name__ == "__main__":
    main()
