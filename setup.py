#!/usr/bin/env python

from setuptools import setup

setup(name="mptcpanalyzer",
      version="0.1",
      description="A complete replacement for i3status",
      url="http://github.com/teto/mptcpanalyzer",
      license="GPL",
      classifiers=[
      ],
      packages=[
          "mptcpanalyzer",
      ],
      entry_points={
          "console_scripts": [
           #   "i3pystatus = i3pystatus:main"
          ]
      },
      zip_safe=True,
      )
