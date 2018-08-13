

|  |  |
| --- | --- |
| Documentation (latest) | [![Dev doc](https://readthedocs.org/projects/pip/badge/?version=latest)](http://mptcpanalyzer.readthedocs.io/en/latest/) |
| Documentation (stable) | [![Master doc](https://readthedocs.org/projects/pip/badge/?version=stable)](http://mptcpanalyzer.readthedocs.io/en/stable/) |
| License | ![License](https://img.shields.io/badge/license-GPL-brightgreen.svg) |
| Build Status | [![Build status](https://travis-ci.org/teto/mptcpanalyzer.svg?branch=master)](https://travis-ci.org/teto/mptcpanalyzer) |
| PyPI |[![PyPI package](https://img.shields.io/pypi/dm/mptcpanalyzer.svg)](https://pypi.python.org/pypi/mptcpanalyzer/) |
| DOI | [![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)|
[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)

Presentation 
===

Mptcpanalyzer is a python (>=3.6) tool conceived to help with MPTCP pcap analysis (as [mptcptrace] for instance). 
It is tested on linux only.

It accepts as input a capture file (.pcap or .pcapng) and from there generates a CSV file 
(thanks to tshark, the terminal version of wireshark) with the MPTCP fields
required for analysis.
From there you can:

- list MPTCP connections
- compute statistics on a specific MPTCP connection (list of subflows,
		reinjections, subflow actual contributions...)
It accepts as input a capture file (\*.pcap) and depending on from there can :
- export a CSV file with MPTCP fields
- plot data sequence numbers for all subflows
- plot DSN interarrival times
- See [Features](#Features) for more

Most commands are self documented and/or with autocompletion.

Then you have an interpreter with autocompletion that can generate & display plots such as the following:

![Data Sequence Number (DSN) per subflow plot](examples/dsn.png)


You can reference mptcpanalyzer via the following Digital Object Identifier:
[![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)

# How to install ?

First of all you will need a wireshark version that supports my MPTCP patches.
See the [next section](#Required-wireshark-version) to check for requirements.

Once wireshark is installed you can install mptcpanalyzer via pip:
`$ python3 -mpip install mptcpanalyzer --user`

python3.6 is mandatory since we rely on its type hinting features.
Dependancies are (some will be made optional in the future):

- [stevedore](http://docs.openstack.org/developer/stevedore/) to handle the
  plugins architecture
- the data analysis library [pandas](http://pandas.pydata.org/) >= 0.17.1
- lnumexpr to run specific queries in pandas
- [matplotlib](http://matplotlib) to plot graphs
- [cmd2](https://github.com/python-cmd2/cmd2) to generate the command line


# Required wireshark version

- [My wireshark patches](https://code.wireshark.org/review/gitweb?p=wireshark.git&a=search&h=HEAD&st=author&s=Coudron)

None pending \o/

You will need a wireshark version that contains:
- [Correctly find reinjections (19 june 2018)](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=commit;h=dac91db65e756a3198616da8cca11d66a5db6db7)

# How to use ?

 mptcpanalyzer can run into 3 modes:
  1. interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.
  2. if a filename is passed as argument, it will load commands from this file
  3. otherwise, it will consider the unknow arguments as one command, the same that could be used interactively

For example, we can load an mptcp pcap (I made one available on [wireshark wiki]
(https://wiki.wireshark.org/SampleCaptures#MPTCP) or in this repository, in the _examples_ folder).

Run  `$ mptcpanalyzer --load examples/iperf-mptcp-0-0.pcap`. The script will try to generate
a csv file, it can take a few minutes depending on your computer.
Then you have a command line: you can type `?` to list available commands. You have for instance:
- `lc` (list connections)
- `ls` (list subflows)
- `plot` 
- ...

`help ls` will return the syntax of the command, i.e. `ls [mptcp.stream]` where mptcp.stream is one of the number appearing 
in `lc` output.

Look at [Examples](#Examples)

# Examples

Plot One Way Delays from a connection 
plot owd_tcp examples/client_2_filtered.pcapng examples/server_2_filtered.pcapng 0 0

# How to contribute

See the [doc](http://mptcpanalyzer.readthedocs.io/en/latest/contributing.html).

# TODO 

- use configobj to load config defaults/validation ?
- as in mptcpplot plot some events (e.g., MP\_JOIN) differently ?
- choose colors of subflows

# Similar tools

If I have forgotten about your tool, file an issue, for know we are aware of:
- [mptcptrace] with some examples [here](http://blog.multipath-tcp.org/blog/html/2015/02/02/mptcptrace_demo.html)
- [mptcpplot] with [generated output example](https://roland.grc.nasa.gov/~jishac/mptcpplot/)


[mptcptrace]: https://bitbucket.org/bhesmans/mptcptrace
[mptcpplot]: https://github.com/nasa/multipath-tcp-tools/
