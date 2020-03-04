# Make it fail if any call fails
set -o errexit
set -x
function gen_transcript()
{
	suffix="$1"
	level="TRACE"
	mptcpanalyzer "-d${LEVEL}" "run_script tests/script_${suffix}.txt -t tests/trans_${suffix}.txt" "quit"
}

gen_transcript "tcp"
gen_transcript "plots_tcp"
gen_transcript "mptcp"
gen_transcript "plots_mptcp"
# gen_transcript "unstable" || true

