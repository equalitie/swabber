#!/usr/bin/env python

import os

class HostsFile(object):

    def __init__(self, path, buffer_writes=0):

        self.filepath = path
        self.hosts_data = None
        self.buffer_writes = buffer_writes

        if buffer_writes:
            self.buffer = []
        else:
            self.buffer = None

    def __load_data(self):
        linedata = []
        with open(self.filepath, "r") as fileobj:
            for line in fileobj.read().split("\n"):
                if line.startswith("#"):
                    continue

                linesplit = line.split()
                if len(linesplit) == 2:
                    # No comment
                    linesplit.append(None)
                if linesplit:
                    linedata.append(linesplit)
        return linedata

    @staticmethod
    def __render_entry(linesplit):
        commentstr = ""

        if linesplit[2] and not linesplit[2].startswith("#"):
            commentstr = "#%s" % linesplit[2]
        elif linesplit[2]:
            commenstr = linesplit[2]

        return "%s %s %s" % (
            linesplit[0],
            linesplit[1],
            commentstr
            )

    def add(self, ipaddress, bantype="ALL", comment=None):
        self.hosts_data = self.__load_data()
        bantype = "%s:" % bantype
        lineentry = self.__render_entry([bantype, ipaddress, comment])

        # if entry is the same, do nothing
        if [bantype, ipaddress, comment] in self.hosts_data:
            return self

        # if entry exists, update/replace.
        for index, entry in enumerate(self.hosts_data):
            if entry[1] == ipaddress:
                self.hosts_data[index][0] = bantype
                self.hosts_data[index][2] = comment
                return self

        if self.buffer_writes:
            self.buffer.append(lineentry)

        # finally, just add it
        if not self.buffer_writes:
            with open(self.filepath, "a") as fileobj:
                fileobj.write(
                    "%s\n" % lineentry
                    )
        elif self.buffer_writes and len(self.buffer) >= self.buffer_writes:
            print "Paging out writes"
            for entry in self.buffer:
                with open(self.filepath, "a") as fileobj:
                    fileobj.write(
                        "%s\n" % entry
                        )

        self.hosts_data += [bantype, ipaddress, comment]

        #TODO: return something better
        return self

    def __add__(self, ipaddress):
        self.hosts_data = self.__load_data()
        comment = None
        bantype = "%s:" % "ALL"
        lineentry = self.__render_entry([bantype, ipaddress, comment])

        # finally, just add it
        with open(self.filepath, "a") as fileobj:
            fileobj.write(
                "%s\n" % lineentry
            )
        self.hosts_data = [bantype, ipaddress, comment]

        #TODO: return something better
        return self

    def __sub__(self, ipaddress):
        out_data = []
        self.hosts_data = self.__load_data()
        for line in self.hosts_data:
            if line[1] != ipaddress:
                out_data.append(line)

        with open(self.filepath, "w") as fileobj:
            for out_line in out_data:
                fileobj.write("%s\n" % self.__render_entry(out_line))

        self.hosts_data = out_data
        #TODO: return something better
        return self

    def __contains__(self, ipaddress):
        self.hosts_data = self.__load_data()
        for line in self.hosts_data:
            if len(line) > 1 and line[1] == ipaddress:
                return True
        return False

    def __len__(self):
        num_lines = 0
        self.hosts_data = self.__load_data()
        for line in self.hosts_data:
            if not line[0].startswith("#"):
                num_lines += 1
        return num_lines

    def __iter__(self):
        self.hosts_data = self.__load_data()
        for line in self.hosts_data:
            yield line

    def __nonzero__(self):
        if self.__len__() > 0:
            return True
        else:
            return False

    #TODO __setitem__
    def __getitem__(self, ipaddress):
        self.hosts_data = self.__load_data()
        for line in self.hosts_data:
            if len(line) > 1 and line[1] == ipaddress:
                return line
        return None

    def __bool__(self):
        return self.__nonzero__()

class HostsDeny(HostsFile):

    def __init__(self, buffer_writes=0):
        HostsFile.__init__(self, "/etc/hosts.deny",
                           buffer_writes=buffer_writes)

class HostsAllow(HostsFile):

    def __init__(self, buffer_writes=0):
        HostsFile.__init__(self, "/etc/hosts.allow",
                           buffer_writes=buffer_writes)

if __name__ == "__main__":
    # this should be a unit test oh well
    a = HostsFile("./hosts.deny")
    sought = "218.108.85.250"
    print len(a)
    if sought in a:
        print "%s is in the file" % sought
    else:
        print "%s is not in the file" % sought

    a -= sought
    if sought in a:
        print "%s is in the file" % sought
    else:
        print "%s is not in the file" % sought

    a += sought
    if sought in a:
        print "%s is in the file" % sought
    else:
        print "%s is not in the file" % sought
