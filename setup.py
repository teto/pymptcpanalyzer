#!/usr/bin/env python
# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:
# Copyright 2015-2016 Universite Pierre et Marie Curie
# Copyright 2017-2018 IIJ Innovation Institute
# Author(s): Matthieu Coudron <coudron@iij.ad.jp>
#
# This file is part of mptcpanalyzer.
#
# mptcpanalyzer is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# mptcpanalyzer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with mptcpanalyzer.  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages

from distutils.cmd import Command
from distutils.core import setup
from distutils.util import convert_path
import sys

# How to package ?
# http://python-packaging-user-guide.readthedocs.org/en/latest/distributing/#setup-py
# http://pythonhosted.org/setuptools/setuptools.html#declaring-dependencies
#
# if something fail during install, try running the script with sthg like
# DISTUTILS_DEBUG=1 python3 setup.py install --user -vvv

main_ns = {} # type: ignore
ver_path = convert_path('mptcpanalyzer/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)
    version = main_ns['__version__']


class RunTests(Command):
    """ Run my command.
    """
    description = "Run tests from the shell"
    user_options = [] # type: ignore

    def initialize_options(self):
        """init options"""
        pass

    def finalize_options(self):
        """finalize options"""
        pass

    def run(self):
        import os
        os.system("make tests")
        sys.exit(1)


setup(name="mptcpanalyzer",
    version=version,
    description="Analyze mptcp traces (.pcap)",
    long_description=open('README.md', 'r', encoding='utf-8').read(),
    url="http://github.com/teto/mptcpanalyzer",
    license="GPL",
    author="Matthieu Coudron",
    author_email="coudron@iij.ad.jp",
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Environment :: Console',
        'Programming Language :: Python :: 3.7',
    ],
    keywords=["mptcp analysis pcap"],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            'mptcpanalyzer = mptcpanalyzer.cli:main',
        ],
        # Each item in the list should be a string with
        # name = module:importable where name is the user-visible name for
        # the plugin, module is the Python import reference for the module,
        # and importable is the name of something that can be imported from
        # inside the module.
        'mptcpanalyzer.plots': [
            'mptcp_attr = mptcpanalyzer.plots.dsn:PlotSubflowAttribute',
            'tcp_attr = mptcpanalyzer.plots.dsn:PlotTcpAttribute',
            'reinject = mptcpanalyzer.plots.reinjections:PlotMpTcpReinjections',
            # 'interarrival = mptcpanalyzer.plots.interarrival:InterArrivalTimes',
            # 'xinterarrival = mptcpanalyzer.plots.interarrival:CrossSubflowInterArrival',
            # 'dss_len = mptcpanalyzer.plots.dss:DssLengthHistogram',
            'dss = mptcpanalyzer.plots.dss:DSSOverTime',
            'owd = mptcpanalyzer.plots.owd:TcpOneWayDelay',
            # 'owd_mptcp = mptcpanalyzer.plots.owd:MpTcpOneWayDelay',
            # 'ns3 = mptcpanalyzer.plots.ns3:PlotTraceSources',
            # 'agg = mptcpanalyzer.plots.aggr_benefit:PlotAggregationBenefit',

            # TODO add gput versions that need merged pcaps
            'tcp_tput = mptcpanalyzer.plots.throughput:SubflowThroughput'
            # 'mptcp_tput = mptcpanalyzer.plots.throughput:MptcpThroughput'
        ],
        # namespace for plugins that monkey patch the main Cmd class
        'mptcpanalyzer.cmds': [
            'stats = mptcpanalyzer.command_example:CommandExample',
        ]
    },
    install_requires=[
        'stevedore',  # to implement a plugin mechanism
        'matplotlib>=3.0.3',  # for plotting
        'pandas',  # >= 0.24.2 because of Int64
        'cmd2>=0.9.12',  # to improve cmd capabilities
        # 'sphinxcontrib-napoleon' # to generate the doc in rtfd.io
    ],
    # TODO to work around pandas bugs: adjust
    # https://stackoverflow.com/questions/3472430/how-can-i-make-setuptools-install-a-package-thats-not-on-pypi
    dependency_links = ['http://github.com/teto/pandas/tarball/master#egg=gearman-2.0.0beta'],
    # test_suite="tests",
    cmdclass={
        "test": RunTests,
    },
    zip_safe=False,
    )
