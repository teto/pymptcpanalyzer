#!/usr/bin/env python
# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:
# Copyright 2015-2016 Université Pierre et Marie Curie
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

class TestCommand(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys, subprocess

        raise SystemExit(
            subprocess.call([sys.executable,
                             '-m',
                             'pisces.test']))
# How to package ?
# http://python-packaging-user-guide.readthedocs.org/en/latest/distributing/#setup-py
# http://pythonhosted.org/setuptools/setuptools.html#declaring-dependencies
# 
# if something fail during install, try running the script with sthg like
# DISTUTILS_DEBUG=1 python3.5 setup.py install --user -vvv

main_ns={}
ver_path = convert_path('mptcpanalyzer/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(name="mptcpanalyzer",
# TODO import version.py
      version=main_ns['__version__'],
      description="Analyze mptcp traces (.pcap)",
      long_description=open('README.md').read(),
      url="http://github.com/lip6-mptcp/mptcpanalyzer",
      license="GPL",
      author="Matthieu Coudron",
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
      # data_files=[
          # ("data", "mptcpanalyzer/mptcp_fields.json"),
      # ],
      entry_points={
          "console_scripts": [
            # creates 2 system programs that can be called from PATH
            'mptcpanalyzer = mptcpanalyzer.cli:cli',
            'mptcpexporter = mptcpanalyzer.exporter:main',
            # 'mptcpnumerics = mptcpanalyzer.analysis:run'
          ],
        # Each item in the list should be a string with name = module:importable where name is the user-visible name for the plugin, module is the Python import reference for the module, and importable is the name of something that can be imported from inside the module.
          'mptcpanalyzer.plots': [
              'misc = mptcpanalyzer.plots.dsn:PerSubflowTimeVsX',
              # 'interdeparture = mptcpanalyzer.plots.dsn:DsnInterArrivalTimes',
              'interarrival = mptcpanalyzer.plots.dsn:InterArrivalTimes',
              'xinterarrival = mptcpanalyzer.plots.dsn:CrossSubflowInterArrival',
              'latency = mptcpanalyzer.plots.latency:LatencyHistogram',
              'dss_len = mptcpanalyzer.plots.dsn:DssLengthHistogram',
              'dss = mptcpanalyzer.plots.dsn:DSSOverTime',
              'owd = mptcpanalyzer.plots.owd:OneWayDelay',
              'ns3 = mptcpanalyzer.plots.ns3:PlotTraceSources',
              ],
          # namespace for plugins that monkey patch the main Cmd class
          # 'mptcpanalyzer.cmds': [
          #     'stats = mptcpanalyzer.stats:DoStats',
          #   ]
      },
      # pandas should include matplotlib dependancy right ?
      install_requires=[
          'stevedore',  # to implement a plugin mechanism
          'matplotlib', # for plotting
          'pandas>=0.17.1', # to load and process csv files
            # those dependancies might made optional later or the package split into two
          # 'sympy', #for symbolic computing
          # 'sortedcontainers' # for the mini mptcp simulator events list

          ],
      # for now the core is not modular enough so just check that running the process produces the same files
      # test_suite="tests",
      #  cmdclass={
      #   'test': TestCommand
      # },
      zip_safe=False,
      )
