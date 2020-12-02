mptcpanalyzer 0.3.3 (dev):
- display resulting plot by default (--display=term|gui|no)
- now loads and expose the interface names
- new plot: congestion windows (in use with mptcp-pm)
- now supports mptcp v1 (can retrieve the key)

mptcpanalyzer 0.3.2:
- TcpConnection now accepts a format to customize its display
- new plots mptcp_tput/mptcp_gput
- renamed tcp_throughput to tcp_tput
- tshark is now launched with an empty wireshark config to prevent interference from
	user modules or lua scripts with the results
- changed CI to work with hercules instead of travis
- bumped cmd2 to 0.9.15
- bumped pandas to 0.25

mptcpanalyzer 0.3.1 (26/03/2019):
- compatibility with cmd 0.9.12 (colorization/autocompletion)
- require python 3.7 to use @dataclass attribute. This allows better static checking
- bumped requirement to pandas >= 0.24.2 because of Int64 changes
- added a `tcp_summary` command
- renamed `summary` to `mptcp_summary`
- now looks for SYNs and SYN/ACK specifically instead of assuming clocks are synchronized
- added a `checkhealth` command to check for python version/wireshark
- plots now display their own help/examples instead of the generic one
- added a tcp_throughput plot


mptcpanalyzer 0.3:
- One Way Delay plotting
- reinjection qualifications

mptcpanalyzer 0.2:

- Boosting requirement for panda to 0.17.1 because of https://github.com/pydata/pandas/issues/11374
