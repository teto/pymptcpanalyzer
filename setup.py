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

from setuptools import setup

# How to package ?
# http://python-packaging-user-guide.readthedocs.org/en/latest/distributing/#setup-py
# http://pythonhosted.org/setuptools/setuptools.html#declaring-dependencies
# 
# if something fail during install, try running the script with sthg like
# DISTUTILS_DEBUG=1 python3.5 setup.py install --user -vvv
setup(name="mptcpanalyzer",
      version="0.1",
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
      ],
      keywords=["mptcp analysis pcap"],
      packages=[
          "mptcpanalyzer", "mptcpanalyzer/plots",
      ],
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
            'mptcpexporter = mptcpanalyzer.exporter:main'
          ]
      },
      # pandas should include matplotlib dependancy right ?
      install_requires=[
          'matplotlib',
          'pandas>=0.17.1'
          ],
      zip_safe=True,
      )
