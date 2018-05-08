#!/usr/bin/env python
# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:
# Copyright 2015-2016 Universite Pierre et Marie Curie
# Copyright 2017-2018 IIJ Innovation Institute
# Author(s): Matthieu Coudron <matthieu.coudron@lip6.fr>
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
# DISTUTILS_DEBUG=1 python3.5 setup.py install --user -vvv

main_ns = {} # type: ignore
ver_path = convert_path('mptcpanalyzer/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)
    version = main_ns['__version__']

if sys.argv[-1] == 'publish':
    import os
    os.system("python setup.py sdist upload")
    os.system("python setup.py bdist_wheel upload")
    print("You probably want to also tag the version now:")
    print("  git tag -a %s -m 'version %s'" % (version, version))
    print("  git push --tags")
    sys.exit()


setup(name="mptcpanalyzer",
      version=version,
      description="Analyze mptcp traces (.pcap)",
      long_description=open('README.md').read(),
      url="http://github.com/lip6-mptcp/mptcpanalyzer",
      license="GPL",
      author="Matthieu Coudron",
      author_email="coudron@iij.ad.jp",
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Science/Research',
          'Intended Audience :: Telecommunications Industry',
          'Environment :: Console',
          'Programming Language :: Python :: 3.5',
          ],
      keywords=["mptcp analysis pcap"],
      packages=find_packages(),
      # [
      # # "mptcpanalyzer", "mptcpanalyzer/plots",
      # ],
      # data files allows to install files outside the package
      # see package_data to add files within pkg
      # package_data=['
      package_data={
          '': ['*.md', "*.json"],
          "mptcpanalyzer": ["toto/mptcp_fields.json"],
          },
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
              'attr = mptcpanalyzer.plots.dsn:PerSubflowTimeVsAttribute',
              # 'interarrival = mptcpanalyzer.plots.interarrival:InterArrivalTimes',
              # 'xinterarrival = mptcpanalyzer.plots.interarrival:CrossSubflowInterArrival',
              # 'dss_len = mptcpanalyzer.plots.dss:DssLengthHistogram',
              'dss = mptcpanalyzer.plots.dss:DSSOverTime',
              'owd_tcp = mptcpanalyzer.plots.owd:TcpOneWayDelay',
              # 'owd_mptcp = mptcpanalyzer.plots.owd:MpTcpOneWayDelay',
              # 'ns3 = mptcpanalyzer.plots.ns3:PlotTraceSources',
              # 'agg = mptcpanalyzer.plots.aggr_benefit:PlotAggregationBenefit',
              'throughput = mptcpanalyzer.plots.throughput:SubflowThroughput'
            ],
          # namespace for plugins that monkey patch the main Cmd class
          'mptcpanalyzer.cmds': [
              'stats = mptcpanalyzer.command_example:CommandExample',
              ]
          },
      install_requires=[
              'stevedore',  # to implement a plugin mechanism
              'matplotlib',  # for plotting
              'pandas>=0.17.1',  # to load and process csv files
              'cmd2',  # to improve cmd capabilities
              'gnureadline',  # to get history capabilities
              # 'mypy',  # for static checking
              # 'sympy',  # for symbolic computation (more of a side project though)
              # 'sphinxcontrib-napoleon' # to generate the doc in rtfd.io
              ],
      # test_suite="tests",
      #  cmdclass={
      #   'test': TestCommand
      # },
      zip_safe=False,
      )
