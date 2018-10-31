#!/bin/sh
# mptcpanalyzer --test /home/teto/mptcpanalyzer/tests/summary.txt
mptcpanalyzer --test tests/summary_server_2_filtered.txt
mptcpanalyzer --test tests/list_mptcp.txt
# mptcpanalyzer --test tests/plot_owd.txt
# mptcpanalyzer --test tests/plot_tcp_attr.txt
