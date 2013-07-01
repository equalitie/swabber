swabber
=======

Simple pubsub-based IP banning engine

To run everything, run swabber.py. 

To just listen for bans, run <code>python banfetcher.py</code>. This will not clean bans (which bancleaner.py will do). 

Installation
======

The following modules must be loaded:
* ip_tables
* ip_conntrack
* iptable_filter
* ipt_state

Python <= 2.5 will need to also install the json module. python-dev is required to install the dependencies. 
