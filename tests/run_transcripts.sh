# to fail on first error
set -e
mptcpanalyzer --test tests/trans_tcp.txt
# mptcpanalyzer --test tests/trans_mptcp.txt
# mptcpanalyzer --test tests/trans_tcp_plots.txt
# mptcpanalyzer --test tests/trans_mptcp_plots.txt
