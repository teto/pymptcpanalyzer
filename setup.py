# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['mptcpanalyzer', 'mptcpanalyzer.plots']

package_data = \
{'': ['*'], 'mptcpanalyzer.plots': ['mappings/*']}

install_requires = \
['PyQt5>=5.15.1,<6.0.0',
 'bitmath @ git+https://github.com/teto/bitmath.git@fix_check',
 'cairocffi>=1.2.0,<2.0.0',
 'cmd2>=1.3',
 'matplotlib==3.3.2',
 'pandas>=1.0',
 'pixcat>=0.1.0',
 'pycairo==1.18.2',
 'pygobject==3.36.1',
 'stevedore']

entry_points = \
{'console_scripts': ['mptcpanalyzer = mptcpanalyzer.cli:main'],
 'mptcpanalyzer.plots': ['cwnds = mptcpanalyzer.plots.cwnd:PlotCwnds',
                         'dss = mptcpanalyzer.plots.dss:DSSOverTime',
                         'mptcp_attr = '
                         'mptcpanalyzer.plots.stream:PlotSubflowAttribute',
                         'mptcp_gput = '
                         'mptcpanalyzer.plots.goodput:MptcpGoodput',
                         'mptcp_tput = '
                         'mptcpanalyzer.plots.throughput:MptcpThroughput',
                         'owd = mptcpanalyzer.plots.owd:TcpOneWayDelay',
                         'reinject = '
                         'mptcpanalyzer.plots.reinjections:PlotMpTcpReinjections',
                         'tcp_attr = '
                         'mptcpanalyzer.plots.stream:PlotTcpAttribute',
                         'tcp_tput = '
                         'mptcpanalyzer.plots.throughput:TcpThroughput']}

setup_kwargs = {
    'name': 'mptcpanalyzer',
    'version': '0.3.4',
    'description': 'Analyze (multipath) TCP packet captures traces (.pcap)',
    'long_description': "\n\n|  |  |\n| --- | --- |\n| Documentation (latest) | [![Dev doc](https://readthedocs.org/projects/pip/badge/?version=latest)](http://mptcpanalyzer.readthedocs.io/en/latest/) |\n| License | ![License](https://img.shields.io/badge/license-GPL-brightgreen.svg) |\n| Build Status | [![Build status](https://travis-ci.org/teto/mptcpanalyzer.svg?branch=master)](https://travis-ci.org/teto/mptcpanalyzer) |\n| PyPI |[![PyPI package](https://img.shields.io/pypi/dm/mptcpanalyzer.svg)](https://pypi.python.org/pypi/mptcpanalyzer/) |\n| DOI |\xa0[![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)|\n[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)\n\n\n\n<!-- BEGIN-MARKDOWN-TOC -->\n* [Presentation](#presentation)\n* [Installation](#installation)\n* [Help](#faq)\n* [Related tools](#related_tools)\n\n<!-- END-MARKDOWN-TOC -->\n\nPresentation\n===\n\nMptcpanalyzer is a python tool conceived to help with MPTCP pcap analysis (as [mptcptrace] for instance).\n\nIt accepts packet capture files (\\*.pcap) as inputs and from there you can:\n\n- list MPTCP connections\n- compute statistics on a specific MPTCP connection (list of subflows, reinjections, subflow actual contributions...)\n- export a CSV file with MPTCP fields\n- plot one way delays\n- ...\n\nCommands are self documented with autocompletion.\nThe interpreter with autocompletion that can generate & display plots such as the following:\n\n![Data Sequence Number (DSN) per subflow plot](examples/dsn.png)\n\n\n# Table of Contents\n\n# Installation\n\nYou will need a wireshark version __>= 3.0.0__ and python >= 3.7\n\nOnce wireshark is installed you can install mptcpanalyzer via pip:\n`$ python3 -mpip install mptcpanalyzer --user`\nor try the development version by:\n```\n$ git clone https://github.com/teto/mptcpanalyzer.git && cd mptcpanalyzer\n$ python3 setup.py develop\n```\n\n# How to use ?\n\n mptcpanalyzer can run into 3 modes:\n  1. interactive mode (default): an interpreter with some basic completion will accept your commands. There is also some help embedded.\n  2. if a filename is passed as argument, it will load commands from this file\n  3. otherwise, it will consider the unknow arguments as one command, the same that could be used interactively\n\nFor example, we can load mptcp pcaps (available at [wireshark wiki](https://wiki.wireshark.org/SampleCaptures#MPTCP) or in this repository `examples` folder).\n\nRun  `$ mptcpanalyzer --load examples/iperf-mptcp-0-0.pcap`. The script will try to generate\na csv file, it can take several seconds depending on the computer/pcap until the prompt shows up.\nType `?` to list available commands (and their aliases). You have for instance:\n- `lc` (list connections)\n- `ls` (list subflows)\n- `plot`\n- ...\n\n`help ls` will return the syntax of the command, i.e. `ls [mptcp.stream]` where mptcp.stream is one of the number appearing\nin `lc` output.\n\nLook at [Examples](#Examples)\n\n# Examples\n\nHead to the [Wiki](https://github.com/teto/mptcpanalyzer/wiki/Examples) for more examples.\n\nPlot One Way Delays from a connection:\n`plot owd tcp examples/client_2_filtered.pcapng 0 examples/server_2_filtered.pcapng 0 --display`\n\nPlot tcp sequence numbers in both directions:\n`plot tcp_attr -h`\n\nGet a summary of an mptcp connection\n```\n> load_pcap examples/server_2_filtered.pcapng\n> mptcp_summary 0\n```\n\n\nMap tcp.stream between server and client pcaps:\n\n```\n>map_tcp_connection examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap  0\nTODO\n>print_owds examples/client_1_tcp_only.pcap examples/server_1_tcp_only.pcap 0 0\n```\n\nMap tcp.stream between server and client pcaps:\n```\n> map_mptcp_connection examples/client_2_filtered.pcapng examples/client_2_filtered.pcapng 0\n2 mapping(s) found\n0 <-> 0.0 with score=inf  <-- should be a correct match\n-tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=inf\n-tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=inf\n-tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=inf\n-tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=inf\n0 <-> 1.0 with score=0\n-tcp.stream 0: 10.0.0.1:33782  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 1: 10.0.0.1:33784  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=30\n-tcp.stream 2: 10.0.0.1:54595  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 3: 10.0.0.1:57491  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=30\n-tcp.stream 4: 11.0.0.1:59555  <-> 11.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 5: 11.0.0.1:50077  <-> 11.0.0.2:05201  (mptcpdest: Server) with score=30\n-tcp.stream 6: 11.0.0.1:35589  <-> 10.0.0.2:05201  (mptcpdest: Server) mapped to tcp.stream 7: 11.0.0.1:50007  <-> 10.0.0.2:05201  (mptcpdest: Server) with score=30\n```\n\n# FAQ\n\nMoved to the [Wiki](https://github.com/teto/mptcpanalyzer/wiki/FAQ)\n\n# How to contribute\n\nPRs welcome !\nSee the [doc](http://mptcpanalyzer.readthedocs.io/en/latest/contributing.html).\n\n\n# Reference\n\nIf you plan to use this tool in a publication,\nYou can reference mptcpanalyzer via the following Digital Object Identifier:\n[![DOI](https://zenodo.org/badge/21021/lip6-mptcp/mptcpanalyzer.svg)](https://zenodo.org/badge/latestdoi/21021/lip6-mptcp/mptcpanalyzer)\n\nor cite:\n```\n@inproceedings{Coudron:2019:PAM:3340422.3343638,\n author = {Coudron, Matthieu},\n title = {Passive Analysis for Multipath TCP},\n booktitle = {Proceedings of the Asian Internet Engineering Conference},\n series = {AINTEC '19},\n year = {2019},\n isbn = {978-1-4503-6849-0},\n location = {Phuket, Thailand},\n pages = {25--32},\n numpages = {8},\n url = {http://doi.acm.org/10.1145/3340422.3343638},\n doi = {10.1145/3340422.3343638},\n acmid = {3343638},\n publisher = {ACM},\n address = {New York, NY, USA},\n keywords = {Multipath TCP, passive analysis, reinjection},\n}\n```\n\n\n# Related tools\n\nSimilar software:\n\n| Tool             | Description                                                                       |\n|------------------------|-------------------------------------------------------------------------------|\n| [mptcptrace]             | C based: [an example](http://blog.multipath-tcp.org/blog/html/2015/02/02/mptcptrace_demo.html)                                               |\n| [mptcpplot]       | C based developed at NASA: [generated output example](https://roland.grc.nasa.gov/~jishac/mptcpplot/)                                                 |\n\n[mptcptrace]: https://bitbucket.org/bhesmans/mptcptrace\n[mptcpplot]: https://github.com/nasa/multipath-tcp-tools/\n",
    'author': 'Matthieu Coudron',
    'author_email': None,
    'maintainer': 'Matthieu Coudron',
    'maintainer_email': None,
    'url': 'http://github.com/teto/mptcpanalyzer',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'entry_points': entry_points,
    'python_requires': '>=3.8,<4.0',
}


setup(**setup_kwargs)
