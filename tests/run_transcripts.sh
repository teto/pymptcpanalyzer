# to fail on first error
set -e
mptcpanalyzer --test tests/trans_tcp.txt
mptcpanalyzer --test tests/trans_mptcp.txt
mptcpanalyzer --test tests/trans_plots_tcp.txt
mptcpanalyzer --test tests/trans_plots_mptcp.txt
