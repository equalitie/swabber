swabber
=======

Simple pubsub-based IP banning engine. Subscribes to a ban publisher, bans the IPs and then unbans them after a while.

To run as a daemon, run swabber.py. Or better yet, start it via the enclosed init script.

Supported methods
-------------
At the moment Swabber supports baning via the [python-iptables](https://github.com/ldx/python-iptables) interface to iptables, by generating and running iptables commands (iptables_cmd) and its own internal method for using /etc/hosts.deny. Banning via iptables is the "proper" way to do things as it will work no matter what and will be managed on a higher level.

Banning via hosts.deny is very lightweight (and will get more lightweight as batching etc is implemented) and requires less dependencies, potentially making for an easier install in very constrained situations. However, use of this file requires services to either be launched via tcpd (not very likely) or to be built with tcp wrapper support (much more likely- most services in Debian, for example).

Debugging
-------------
Swabber will not daemonise and log to stdout in a verbose manner when run with <code>-v</code> as an argument.

To just listen for bans, run <code>python banfetcher.py</code>. This will not clean bans (which running bancleaner.py in the same way will do). There are no arguments to these individual scripts and the options are inherited from constants defined within the scripts themselves.

Hacking
-------------
The banpub-faker.py script is an example of a ban publisher if you fancy implementing one. It's just that simple. Be careful about your high water marks for the ZMQ depending on what your system is capable of.

Installation
======
Python <= 2.5 will need to also install the json module. python-dev is required to install the dependencies.

The Debian 9 dependencies can be installed via apt:

    apt-get install iptables python-iptables python-zmq python-yaml python-ipaddr

The python-iptables package has a bug which prevents it loading the <code>libxtwrapper.so</code> module. The following symbolic link fixes the load:

    ln -s /usr/lib/python2.7/dist-packages/libxtwrapper.x86_64-linux-gnu.so /usr/lib/python2.7/dist-packages/libxtwrapper.so

NB: On Debian 9, you may need to create the <code>/usr/local/lib/python2.7/dist-packages</code> directory by hand.

<code>setuptools</code> can be used to install the actual swabber daemon to <code>/usr/bin/swabberd.py</code>:

    python setup.py install


The <code>swabberd</code> file can be used as an init script if you're installing the package by hand.


The SystemD service file can be used to manage the swabber daemon. It can be installed as follows:


    cp ../initscript/swabberd.service /lib/systemd/system/swabber.service

    systemctl enable swabber
    systemctl start swabber
    systemctl status swabber



The <code>banpub-faker.py</code> example publisher also requires the Tornado Python library which can be installed with:

    apt-get install python-tornado


iptables interface
-------------
The following modules must be loaded on Debian wheezy:
* ip_conntrack
* iptable_filter
* ipt_state

Setup for your system will probably be different if you are on another distro, depending on how your kernel was compiled.

Configuration
======
/etc/swabber.yaml (or whatever you point to with <code>python swabberd.py -c conf/myconf.yaml</code> is where Swabber gets its configuration from.

There are currently only four configurable options:

bantime: <integer>
-------------
The number of seconds to hold a ban before unbanning a host. As of the time of writing, this is at the possibly sensible value of three hours. It is recommended you set this higher but beware of the ineviable overhead that comes from maintaining huge lists of bans. Setting a bantime of 0 will mean that bans will never be cleaned.

[Currently](https://github.com/ldx/python-iptables/issues/38) python-iptables can encounter some CPU issues when iterating over huge lists of bans. /etc/hosts.deny can incur some overhead when a huge number of entries is present (64000 bans can incur .1s of connection delay, although a figure this large is not recommended).

polltime: <integer>
-------------
How often to check for existing bans to unban. The default of 60 is a relatively sane one, but if you need very short-term bans then changing this might be of use.

bindstrings: [<ZMQ connection URI>...]
-------------
A list of strings to subscribe to bans on. This defaults to <code>[tcp://127.0.0.1:22620]</code> and won't really be required to be configured for day to day operations. Those who choose to hack around with Swabber may get some use out of this however. To use multiple applications with Swabber, use multiple bindstrings. Caution is __strongly__ advised when using strings with IP addresses other than 127.0.0.1 - Swabber offers no authentication on this interface by design and an attacker with half a brain will probably ban stuff for fun.

interface: <iptables match>
-------------
*iptables and iptables_cmd interfaces only*

This is the interface to issue ban rules for. Can be of the iptables match format- it already defaults to eth+, for example.

backend: hostsfile OR iptables OR iptables_cmd
-------------
Ban hosts using /etc/hosts.deny, the python-iptables module or directly via iptables commands. See above for the explanation of the impact of this option.
