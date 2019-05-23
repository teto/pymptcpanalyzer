# Make it fail if any call fails
set -o errexit
function gen_transcript()
{
	suffix="$1"
	mptcpanalyzer "load tests/script_${suffix}.txt -t tests/trans_${suffix}.txt" "quit"
}

gen_transcript "tcp"
gen_transcript "mptcp"
# gen_transcript "plots_mptcp"
# gen_transcript "plots_tcp"
# gen_transcript "reinjections" || true
# gen_transcript "unstable" || true

