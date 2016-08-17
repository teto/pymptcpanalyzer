Configuration
==================================================

mptcpanalyzer accepts few parameters that can be recorded in a configuration file.
The file can be specified on the command line via the '--config' (or '-c') switch:

.. code-block:: console
    :caption: Editing config

    $ mptcpanalyzer --config myconfig.cfg

By default, mptcpanalyzer will try to load the config file first in $XDG_CACHE_HOME/mptcpanalyzer/config, then in 
$HOME/.config/mptcpanalyzer/config.


.. literalinclude:: /../../../examples/config


* delimiter is the csv separator used by thsark when exporting the pcap
* styleX follow matplotlib conventions to set lines color/style
* tshark_bin in case you want to run a specific tshark binary

