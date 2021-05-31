

|  |  |
| --- | --- |
| Documentation (latest) | [![Dev doc](https://readthedocs.org/projects/pip/badge/?version=latest)](http://mptcpanalyzer.readthedocs.io/en/latest/) |
| License | ![License](https://img.shields.io/badge/license-GPL-brightgreen.svg) |
| Build Status | [![Build status](https://travis-ci.org/teto/mptcpanalyzer.svg?branch=master)](https://travis-ci.org/teto/mptcpanalyzer) |
| PyPI |[![PyPI package](https://img.shields.io/pypi/dm/mptcpanalyzer.svg)](https://pypi.python.org/pypi/mptcpanalyzer/) |
| DOI | [![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)|
[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)



<!-- BEGIN-MARKDOWN-TOC -->
* [Presentation](#presentation)
* [Installation](#installation)
* [Help](#faq)
* [Related tools](#related_tools)

<!-- END-MARKDOWN-TOC -->

Presentation
===

Mptcpanalyzer is a python tool conceived to help with MPTCP pcap analysis (as [mptcptrace] for instance).

It accepts packet capture files (\*.pcap) as inputs and from there you can:

- list MPTCP connections
- compute statistics on a specific MPTCP connection (list of subflows, reinjections, subflow actual contributions...)
- export a CSV file with MPTCP fields
- plot one way delays
- ...

Commands are self documented with autocompletion.
The interpreter with autocompletion that can generate & display plots such as the following:

![Data Sequence Number (DSN) per subflow plot](examples/dsn.png)


# Table of Contents

# Installation

You will need a wireshark version __>= 3.0.0__ and python >= 3.7

Once wireshark is installed you can install mptcpanalyzer via pip:
`$ python3 -mpip install mptcpanalyzer --user`
or try the development version by:
```
$ git clone https://github.com/teto/mptcpanalyzer.git && cd mptcpanalyzer
$ poetry install    # (or "python3 setup.py develop" if you use pip)
```

# or if you use nix

```
$ nix develop
$ export PYTHONPATH="$PWD:$PYTHONPATH"
```

# How to use ?

 mptcpanalyzer can run into 3 modes:
  1. interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.
  2. if a filename is passed as argument, it will load commands from this file
  3. otherwise, it will consider the unknow arguments as one command, the same that could be used interactively

For example, we can load mptcp pcaps (available at [wireshark wiki](https://wiki.wireshark.org/SampleCaptures#MPTCP) or in this repository `examples` folder).

Run  `$ mptcpanalyzer --load examples/iperf-mptcp-0-0.pcap`. The script will try to generate
a csv file, it can take several seconds depending on the computer/pcap until the prompt shows up.
Type `?` to list available commands (and their aliases). You have for instance:
- `lc` (list connections)
- `ls` (list subflows)
- `plot`
- ...

`help ls` will return the syntax of the command, i.e. `ls [mptcp.stream]` where mptcp.stream is one of the number appearing
in `lc` output.

Look at [Examples](#Examples)

# Examples

Head to the [Wiki](https://github.com/teto/mptcpanalyzer/wiki/Examples) for more examples.

Plot One Way Delays from a connection:
`plot owd tcp examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0 --display`

Plot tcp sequence numbers in both directions:
`plot tcp_attr -h`

Get a summary of an mptcp connection
```
> load_pcap examples/server_2_filtered.pcapng
> mptcp_summary 0
```


Map tcp.stream between server and client pcaps:

```
>map_tcp_connection examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap  0
TODO
>print_owds examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap 0 0
```

Map tcp.stream between server and client pcaps:
```
> map_mptcp_connection examples/client_2_filtered.pcapng examples/client_2_filtered.pcapng 0
2 mapping(s) found
0 <-> 0.0 with score=inf  <-- should be a correct match
-tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=inf
-tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=inf
-tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=inf
-tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=inf
0 <-> 1.0 with score=0
-tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 1: 10.0.0.1:33784  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=30
-tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 3: 10.0.0.1:57491  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=30
-tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 5: 11.0.0.1:50077  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=30
-tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 7: 11.0.0.1:50007  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=30
```

# FAQ

Moved to the [Wiki](https://github.com/teto/mptcpanalyzer/wiki/FAQ)

# How to contribute

PRs welcome !
See the [doc](http://mptcpanalyzer.readthedocs.io/en/latest/contributing.html).


# Reference

If you plan to use this tool in a publication,
You can reference mptcpanalyzer via the following Digital Object Identifier:
[![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)

or cite:
```
@inproceedings{Coudron:2019:PAM:3340422.3343638,
 author = {Coudron, Matthieu},
 title = {Passive Analysis for Multipath TCP},
 booktitle = {Proceedings of the Asian Internet Engineering Conference},
 series = {AINTEC '19},
 year = {2019},
 isbn = {978-1-4503-6849-0},
 location = {Phuket, Thailand},
 pages = {25--32},
 numpages = {8},
 url = {http://doi.acm.org/10.1145/3340422.3343638},
 doi = {10.1145/3340422.3343638},
 acmid = {3343638},
 publisher = {ACM},
 address = {New York, NY, USA},
 keywords = {Multipath TCP, passive analysis, reinjection},
}
```


# Related tools

Similar software:

| Tool             | Description                                                                       |
|------------------------|-------------------------------------------------------------------------------|
| [mptcptrace]             | C based: [an example](http://blog.multipath-tcp.org/blog/html/2015/02/02/mptcptrace_demo.html)                                               |
| [mptcpplot]       | C based developed at NASA: [generated output example](https://roland.grc.nasa.gov/~jishac/mptcpplot/)                                                 |

[mptcptrace]: https://bitbucket.org/bhesmans/mptcptrace
[mptcpplot]: https://github.com/nasa/multipath-tcp-tools/
