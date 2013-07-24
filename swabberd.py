#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

from swabber import BanCleaner
from swabber import BanFetcher
from swabber import banobjects

import daemon
import sqlalchemy
import yaml

import threading
import lockfile
import logging
import optparse
import sys

def getConfig(configpath): 
    config_h = open(configpath)
    config = yaml.load(config_h.read())
    config_h.close()

    if "db_conn" not in config: 
        config["db_conn"] = 'sqlite:///swabber.db'
    if "bantime" not in config: 
        # minutes
        config["bantime"] = 2
    if "bindstring" not in config:
        config["bindstring"] = "tcp://127.0.0.1:22620"
    if "interface" not in config:
        config["interface"] = "eth+"

    return config

def runThreads(configpath, verbose):
    config = getConfig(configpath)

    #TODO initialise DB
    try:
        banobjects.createDB(config["db_conn"])
    except sqlalchemy.exc.OperationalError:
        logging.error("Couldn't create DB! Is path valid for %s?", config["db_conn"])
        return False

    iptables_lock = threading.Lock()

    cleaner = BanCleaner(config["db_conn"], config["bantime"], iptables_lock)
    banner = BanFetcher(config["db_conn"], config["bindstring"], 
                        config["interface"], iptables_lock)
    try:
        cleaner.start()
        logging.warning("Started running cleaner")
        banner.start()
        logging.warning("Started running banner")
    except Exception as e:
        logging.error("Swabber exiting on exception %s!", str(e))
        cleaner.running = False
        banner.running = False

def main(): 
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Be verbose in output, don't daemonise", 
                      action="store_true")

    parser.add_option("-c", "--config",
                      action="store", dest="configpath", 
                      default="/etc/swabber.yaml",
                      help="alternate path for configuration file")
    
    (options, args) = parser.parse_args()

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
