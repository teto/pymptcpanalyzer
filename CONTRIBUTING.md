# How to contribute to mptcpanalyzer ?

Submission of code should be done via the github pull requests system.

mptcpanalyzer can load plugins following stevedore's [plugin](http://docs.openstack.org/developer/stevedore/tutorial/creating_plugins.html#adding-plugins-in-other-packages), i.e. mptcpanalyzer will look for specific disttools entry points
in order to find and load plugins.

To add a plugin, just mimic what is done for existing plugins, see stevedore's
plugin documentation plus check our setup.py:
```
      entry_points={
          "console_scripts": [
            # creates 2 system programs that can be called from PATH
            'mptcpanalyzer = mptcpanalyzer.cli:cli',
            'mptcpexporter = mptcpanalyzer.exporter:main'
          ],
        # Each item in the list should be a string with name = module:importable where name is the user-visible name for the plugin, module is the Python import reference for the module, and importable is the name of something that can be imported from inside the module.
          'mptcpanalyzer.plots': [
              'dsn = mptcpanalyzer.plots.dsn:TimeVsDsn',
              'latency = mptcpanalyzer.plots.latency:LatencyHistogram',
              ],
          # namespace for plugins that monkey patch the main Cmd class
          'mptcpanalyzer.cmds': [
              'stats = mptcpanalyzer.stats:DoStats',
            ]
      },
```

mptcpanalyzer will load all plugins residing in these two namespaces:
- mptcpanalyzer.plots 
- mptcpanalyzer.cmds
regardless of their package.

In order to test while modifying mptcpanalyzer, you should install it like this: 
$ python3.5 setup.py develop --user

# How to upload it to pypy (for the forgetful maintainer)
python3.5 setup.py sdist upload
(test first the package locally pip install /path/toarchive.gz)
