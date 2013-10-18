#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

from swabber import BanCleaner
from swabber import BanFetcher
from swabber import banobjects

import daemon
import yaml

import threading
import lockfile
import logging
import optparse
import os
import sys

BACKENDS = ["iptables", "hostsfile", "iptables_cmd"]

def getConfig(configpath): 
    config_h = open(configpath)
    config = yaml.load(config_h.read())
    config_h.close()
    
    # defaults
    if "bantime" not in config: 
        # minutes
        config["bantime"] = 2
    if "bindstring" not in config:
        config["bindstring"] = "tcp://127.0.0.1:22620"
    if "interface" not in config:
        config["interface"] = "eth+"
    if "backend" not in config:
        config["backend"] = "iptables"

    if config["backend"] not in BACKENDS: 
        raise ValueError("%s is not in backends: %s", 
                         config["backend"], 
                         ", ".join(BACKENDS))

    return config

def runThreads(configpath, verbose):
    config = getConfig(configpath)

    iptables_lock = threading.Lock()

    #TODO make iptables_lock optional
    cleaner = None
    if config["bantime"] != 0:
        cleaner = BanCleaner(config["bantime"], config["backend"], 
                             iptables_lock)
    banner = BanFetcher(config["bindstring"], 
                        config["interface"], config["backend"], 
                        iptables_lock)
    try:
        if config["bantime"] != 0:
            cleaner.start()
            logging.warning("Started running cleaner")
        banner.start()
        logging.warning("Started running banner")
    except Exception as e:
        print "Exception %s" % e
        logging.error("Swabber exiting on exception %s!", str(e))
        if config["bantime"] != 0:
            cleaner.stopIt()
        banner.stopIt()

def main(): 


    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Be verbose in output, don't daemonise", 
                      action="store_true")
    parser.add_option("-F", "--force", dest="forcerun",
                      help="Try to run when not root", 
                      action="store_true")

    parser.add_option("-c", "--config",
                      action="store", dest="configpath", 
                      default="/etc/swabber.yaml",
                      help="alternate path for configuration file")
    
    (options, args) = parser.parse_args()

    if os.getuid() != 0 and not options.forcerun: 
        sys.stderr.write("Not running as I need root access - use -F to force run\n")
        sys.exit(1)

    if not os.path.isfile(options.configpath): 
        sys.stderr.write("Couldn't load config file %s!\n" % options.configpath)
        sys.exit(1)

    if not options.verbose:
        with daemon.DaemonContext(pidfile=lockfile.FileLock('/var/run/swabber.pid')):
            logging.info("Starting swabber in daemon mode")
            runThreads(options.configpath, options.verbose)
    else:
        mainlogger = logging.getLogger()
        
        logging.basicConfig(level=logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        mainlogger.addHandler(ch)
        runThreads(options.configpath, options.verbose)

if __name__ == "__main__":
    main()
