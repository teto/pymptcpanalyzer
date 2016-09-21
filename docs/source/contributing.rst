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

Regardless of which python package they belong.

In order to test while modifying mptcpanalyzer, you can install it like this: 

.. code-block:: console

    $ python3.5 setup.py develop --user

.. note :: Add --uninstall to remove the installation.

Develop a new plot
------------------------------------------------------------

You must create a new class that inherits from :py:class:`mptcpanalyzer.plot.Plot` 
(or one of its children).
I recommend to inherit from :class:`mptcpanalyzer.plot.Matplotlib` which provides 
some additional features.

The easiest way to start is to copy the source code of `.plot.PerSubflowTimeVsAttribute` 
and change the `plot` function. Once this is done, you should update :file:setup.py and
add an entry in the **mptcpanalyzer.cmds** namespace as is done for the other plots.

Everything else should be taken care of by mptcpanalyzer: congratulations you finished your first plot !

If you want to change the parser, you can also override the `default_parser` member.

.. note: It is in general a good idea to inherit from the parent parser so call parser = super().default_parser first.


.. .. automodule:: mptcpanalyzer.plot
..     :members:  

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


