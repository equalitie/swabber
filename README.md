swabber
=======

Simple pubsub-based IP banning engine

To run everything, run swabber.py. 

To just listen for bans, run <code>python banfetcher.py</code>. This will not clean bans (which running bancleaner.py in the same way will do). 

Installation
======

The following modules must be loaded:
* ip_tables
* ip_conntrack
* iptable_filter
* ipt_state

Python <= 2.5 will need to also install the json module. python-dev is required to install the dependencies. 

<code>python setup.py install</code> will install the libraries and the actually swabber daemon. The <code>swabberd</code> file can be used as an init script if you're installing the package by hand. 
