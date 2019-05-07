
function gen_transcript()
{
	suffix="$1"
	mptcpanalyzer "load tests/script_${suffix}.txt -t tests/trans_${suffix}.txt" "quit"
}

gen_transcript "tcp"
gen_transcript "mptcp"
gen_transcript "plots_mptcp"
gen_transcript "plots_tcp"
gen_transcript "unstable" || true
# tests/run_transcripts.sh
# mptcpanalyzer "load tests/script_mptcp.txt -t tests/trans_mptcp.txt" "quit"
# mptcpanalyzer "load tests/script_plots_tcp.txt -t tests/trans_plots_tcp.txt" "quit"
# mptcpanalyzer "load tests/script_plots_mptcp.txt -t tests/trans_plots_mptcp.txt" "quit"
