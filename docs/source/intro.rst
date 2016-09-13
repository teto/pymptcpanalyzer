
Introduction
========================================



Features
----------------------------------------

 
* list the MPTCP connections in the pcap
* display some statistics on a specific MPTCP connection (list of subflows etc...)
It accepts as input a capture file (\*.pcap) and depending on from there can :
* pcap to csv conversion 
* plot data sequence numbers for all subflows
* `XDG compliance <http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html>`_, i.e., 
  |prog| looks for files in certain directories. will try to load your configuration from `$XDG_CONFIG_HOME/mptcpanalyzer/config`
* caching mechanism: mptcpanalyzer compares your pcap creation time and will
  regenerate the cache if it exists in `$XDG_CACHE_HOME/mptcpanalyzer/<path_to_the_file>`
* support 3rd party plugins (plots or commands)

Most commands are self documented and/or with autocompletion.

Then you have an interpreter with autocompletion that can generate & display plots such as the following:

![Data Sequence Number (DSN) per subflow plot](examples/dsn.png)




How to install ?
----------------------------------------

First of all you will need a wireshark version that supports MPTCP dissection,
i.e., wireshark > 2.1.0. If you are on ubuntu, there are dev builds on
https://launchpad.net/~dreibh/+archive/ubuntu/ppa/.

Once wireshark is installed you can install mptcpanalyzer via pip:

command:`$ python3.5 -mpip install mptcpanalyzer --user`

python3.5+ is mandatory since we rely on its type hinting features.
Dependancies are (some will be made optional in the future):

- `stevedore <http://docs.openstack.org/developer/stevedore/>`_ to handle the
  plugins architecture
- the data analysis library `pandas <http://pandas.pydata.org/>`_ >= 0.17.1
- `matplotlib <http://matplotlib>`_ to plot graphs
- (lnumexpr to run specific queries in pandas)

How does it work (internals) ?
----------------------------------------

mptcpanalyzer consists of small python scripts. the heavy task is done by wireshark.
It relies on tshark (terminal version of wireshark) to convert pcap to csv files.

It accepts as input a pcap (or csv file following a proper format). 
Upon pcap detection, mptcpanalyzer the formats supported by tshark (terminal version of wireshark).
