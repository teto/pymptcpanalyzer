doc:
	make -C docs html

test:
	python3.5 setup.py test

install:
	python3.5 setup.py develop --user

uninstall:
	python3.5 setup.py develop --user --uninstall

man:
	# wrong name for the program but can't override :/
	help2man -n "mptcpanalyzer - a multipath tcp pcap analysis tool" -o docs/mptcpanalyzer.man mptcpanalyzer/cli.py


.PHONY: doc
