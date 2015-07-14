#!/usr/bin/python

"""

 Swabber is a daemon for management of IP bans. The bans are
accepted over a 0mq interface (or interfaces) and are expired after a
period of time.

I wrote this code in a simpler time, and now I am quite ashamed
of a lot of it. It all needs a rewrite.

"""

__author__ = "nosmo@nosmo.me"

from swabber import BanCleaner
from swabber import BanFetcher

import yaml

import logging
import optparse
import os
import signal
import sys
import threading

BACKENDS = ["iptables", "hostsfile", "iptables_cmd"]

DEFAULT_CONFIG = {
    "bantime": 120,
    "bindstrings": ["tcp://127.0.0.1:22620"],
    "interface": "eth+",
    "backend": "iptables",
    "logpath": "/var/log/swabber.log"
}

def get_config(configpath):
    config = DEFAULT_CONFIG

    with open(configpath) as config_h:
        config.update(yaml.safe_load(config_h.read()))

    if config["backend"] not in BACKENDS:
        raise ValueError("%s is not in backends: %s",
                         config["backend"],
                         ", ".join(BACKENDS))
    return config

def run_threads(config):

    #TODO make iptables_lock optional
    iptables_lock = threading.Lock()

    cleaner = None
    if config["bantime"] != 0:
        cleaner = BanCleaner(config["bantime"], config["backend"],
                             iptables_lock, config["interface"])
    banner = BanFetcher(config["bindstrings"],
                        config["interface"], config["backend"],
                        iptables_lock)

    def handle_signal(signum, frame):
        if signum == 15 or signum == 16:
            banner.stop_running()
            if config["bantime"]:
                cleaner.stopIt()
            logging.warning("Closing on SIGTERM")
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        if config["bantime"] != 0:
            cleaner.start()
            logging.warning("Started running cleaner")
        banner.start()
        logging.warning("Started running banner")
    except Exception as e:
        print "Exception %s" % e
        logging.error("Swabber exiting on exception %s!", str(e))
        if config["bantime"]:
            cleaner.stop_running()
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
    config = get_config(options.configpath)

    if options.verbose:
        mainlogger = logging.getLogger()

        logging.basicConfig(level=logging.DEBUG)
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(logging.Formatter(
            'swabber (%(process)d): %(levelname)s %(message)s'))
        mainlogger.addHandler(ch)
    else:
        # Set up logging
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        logfile_handler = logging.handlers.WatchedFileHandler(config["logpath"])
        logfile_handler.setFormatter(logging.Formatter(
            'swabber (%(process)d): %(levelname)s %(message)s'))
        logger.addHandler(logfile_handler)

    if os.getuid() != 0 and not options.forcerun:
        sys.stderr.write("Not running as I need root access - use -F to force run\n")
        sys.exit(1)

    if not os.path.isfile(options.configpath):
        sys.stderr.write("Couldn't load config file %s!\n" % options.configpath)
        sys.exit(1)

    if not options.verbose:
        if os.fork() != 0:
            raise SystemExit("Couldn't fork!")
        if os.fork() != 0:
            raise SystemExit("Couldn't fork!")

        with open("/var/run/swabberd.pid", "w") as mypid:
            mypid.write(str(os.getpid()))

        logging.info("Starting swabber in daemon mode")

    run_threads(config)

if __name__ == "__main__":
    main()
