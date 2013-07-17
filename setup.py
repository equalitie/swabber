import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "swabber",
    version = "1.0.0",
    author = "Hugh Nowlan",
    author_email = "nosmo@nosmo.me",
    description = "Pubsub-based host banning interface",
    license = "N(C)",
    keywords = "iptables banning pubsub",
    url = "http://github.com/equalitie/swabber",
    packages=['swabber'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Daemons",
        "License :: N(C) License",
        ],
    scripts = ["swabberd.py"], 
    data_files=[
        ('/etc', ["conf/swabber.yaml"]), 
        ('/etc/init.d/', ["swabberd"])
        ],
    )
