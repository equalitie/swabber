import os
from setuptools import setup

setup(
    name = "swabber",
    version = "1.3.7",
    author = "Hugh Nowlan",
    author_email = "nosmo@nosmo.me",
    description = "Pubsub-based host banning interface",
    license = "N(C)",
    keywords = "iptables banning pubsub",
    url = "http://github.com/equalitie/swabber",
    packages=['swabber'],
    install_requires=[
        "python-iptables",
        "pyzmq",
        "ipaddr",
        "pyyaml"
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Security",
        "Intended Audience :: System Administrators",
        ],
    scripts = ["swabberd"],
    # Not distributing configuration and init script with the package
    # because data_files is fucking USELESS. Can't rename files, can't
    # address files with a relative path, must have the init script with the
    # same name as the actual script getting installed into bin/. Fuck
    # that, fuck off, fuck computers.
    )
