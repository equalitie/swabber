#!/usr/bin/env python

__author__ = "nosmo@nosmo.me"

from swabber import BanCleaner
from swabber import BanFetcher
from swabber import banobjects

import daemon
import logging
import optparse
import yaml

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

    return config

def runThreads(configpath, verbose):
    config = getConfig(configpath)

    #TODO initialise DB
    banobjects.createDB(config["db_conn"])

    cleaner = BanCleaner(config["db_conn"], config["bantime"])
    banner = BanFetcher(config["db_conn"], config["bindstring"])
    cleaner.run()
    logging.warning("Started running cleaner")
    banner.run()
    logging.warning("Started running banner")

def main(): 
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Be verbose in output, don't daemonise", 
                      action="store_true")
    parser.add_option("-c", "--config",
                      action="store", dest="configpath", 
                      default="../conf/swabber.yaml",
                      help="alternate path for configuration file")
    
    (options, args) = parser.parse_args()

    if not options.verbose:
        with daemon.DaemonContext():
            logging.info("Starting swabber in daemon mode")
            runThreads(options.configpath, options.verbose)
    else:
        runThreads(options.configpath, options.verbose)

if __name__ == "__main__":
    main()
