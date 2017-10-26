all:
	# disabled

doc:
	make -C docs html

# pypi accepts only rst
# see http://inre.dundeemt.com/2014-05-04/pypi-vs-readme-rst-a-tale-of-frustration-and-unnecessary-binding/
rst:
	cat README.md | pandoc -f markdown -t rst > README.rst


test:
	# Add -b to print standard output
	python3 -munittest tests/cache_test.py -b 
	python3.5 setup.py test

install:
	python3.5 setup.py develop --user

uninstall:
	python3.5 setup.py develop --user --uninstall

man:
	# wrong name for the program but can't override :/
	# see also rst2man in docutils*.deb
	help2man -n "mptcpanalyzer - a multipath tcp pcap analysis tool" -o docs/mptcpanalyzer.man mptcpanalyzer


.PHONY: doc
