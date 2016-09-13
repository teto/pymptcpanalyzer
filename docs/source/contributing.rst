How to contribute to mptcpanalyzer ?
****************************************

There are several things you can do:

* submit bug reports in our `tracker <https://github.com/lip6-mptcp/mptcpanalyzer/issues>`_
* :ref:`develop-new-plugins`, if you do, please warn us so that we can add you to the list of plugins
* `Send patches <https://github.com/lip6-mptcp/mptcpanalyzer/pulls>`_ to either fix a bug, improve the documentation or flake8 compliance 


.. _develop-new-plugins:

Develop an mptcpanalyzer plugin 
===============================
|prog|_ can load plugins following `stevedore's plugin <http://docs.openstack.org/developer/stevedore/tutorial/creating_plugins.html#adding-plugins-in-other-packages>`_, i.e. mptcpanalyzer will look for specific disttools entry points
in order to find and load plugins.

To add a plugin, just mimic what is done for existing plugins, see stevedore's
plugin documentation plus check our setup.py:


.. literalinclude:: /../../setup.py
    :emphasize-lines: 1,11
    :linenos:
    :lines: 91-103


|prog| will load all plugins residing in these two namespaces:

- **mptcpanalyzer.plots**
- **mptcpanalyzer.cmds**

regardless of which python package they belong

In order to test while modifying mptcpanalyzer, you can install it like this: 

.. code-block:: console

    $ python3.5 setup.py develop --user

.. note :: Add --uninstall to remove the installation.

Develop a new plot
------------------------------------------------------------

You must create a new class that inherits from :py:class:`mptcpanalyzer.plot.Plot` 
(or one of its children).
Then you most likely need to override.

.. automodule:: mptcpanalyzer.plot
    :members:  

Develop a command plugin
------------------------------------------------------------

Just follow the example in:

.. literalinclude:: /../../mptcpanalyzer/command_example.py
    :linenos:

.. automodule:: mptcpanalyzer.command_example


How to upload it to pypy (for the forgetful maintainer)
--------------------------------------------------------------------------------

.. code-block:: console

    $ python3.5 setup.py sdist upload


(test first the package locally pip install /path/toarchive.gz)


