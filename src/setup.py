import os
from setuptools import setup

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

    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Security",
        "Intended Audience :: System Administrators",
        ],
    scripts = ["swabberd"],
    data_files=[
        ('/etc', ["../conf/swabber.yaml"]),
        ('/etc/init.d/', ["../initscript/swabberd"])
        ],
    )
