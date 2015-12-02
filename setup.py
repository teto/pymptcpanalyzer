#!/usr/bin/env python
# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:

# Copyright 2015-2015 Matthieu Coudron <matthieu.coudron@lip6.fr>
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

setup(name="mptcpanalyzer",
      version="0.1",
      description="Analyze mptcp traces (.pcap)"
      url="http://github.com/teto/mptcpanalyzer",
      license="GPL",
      author="Matthieu Coudron",
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: System Administrators',
          'Environment :: Console',
      ],
# py_modules
      packages=[
          "mptcpanalyzer",
      ],
      data_files=[
          ("", "mptcpanalyzer/mptcp_fields.json"),
      ]
      entry_points={
          "console_scripts": [
           #   "i3pystatus = i3pystatus:main"
                      # ['qutebrowser = qutebrowser.qutebrowser:main']},
          ]
      },
      install_requires=['matplotlib', 'pandas'],
      zip_safe=True,
      # package_data=['
      scripts=['exporter.py']
      )
