#!/usr/bin/env python

import daemon
import optparse
import yaml

def getConfig(configpath): 
    config_h = open(configpath)
    config = yaml.loads(config_h.read())
    config_h.close()

    if "db_conn" not in config: 
        config["db_conn"] = 'sqlite:///swabber.db'
    if "bantime" not in config: 
        # minutes
        config["bantime"] = 2
    if "bindstring" not in config:
        config["bindstring"] = "tcp://127.0.0.1:22620"

    return configpath

def runThreads(configpath, verbose):
    config = getConfig(configpath)

    cleaner = BanCleaner(config["db_conn"], config["bantime"])
    banner = BanFetcher(config["db_conn"], config["bindstring"])
    cleaner.run()
    logging.debug("Started running cleaner")
    banner.run()
    logging.debug("Started running banner")

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose",
                      help="Be verbose in output", action="store_true")
    parser.add_option("-c", "--config",
                      action="store", dest="configpath", default="./swabber.yaml",
                      help="alternate path for configuration file")
    
    (options, args) = parser.parse_args()

    if not options.verbose:
        with daemon.DaemonContext():
            runThreads(options.configpath, options.verbose)
    else:
        runThreads(options.configpath, options.verbose)
