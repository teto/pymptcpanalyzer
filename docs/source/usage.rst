Usage
========================================

This package installs 2 programs:
- *mptcpanalyzer* to get details on a loaded pcap.
  
  
mptcpanalyzer can run into 3 modes:
  1. :ref:`interactive-mode` (default): an interpreter with some basic completion will accept your commands. 
  2. :ref:`batch-mode` if a filename is passed as argument, it will load commands from this file.
  3. :ref:`oneshot`, it will consider the unknow arguments as one command, the same that could be used interactively

For example, we can load an mptcp pcap (I made one available on `wireshark wiki 
<https://wiki.wireshark.org/SampleCaptures#MPTCP>`_ or in this repository, in the _examples_ folder).

It expects a trace to work with. If the trace has the form *XXX.pcap* extension, the script will look for its csv counterpart *XXX.pcap.csv*. The program will tell you what arguments are needed. Then you can open the generated graphs.



.. _interactive-mode:

Interactive mode
----------------------------------------

Run  `$ mptcpanalyzer --load examples/iperf-mptcp-0-0.pcap`. The script will try to generate
a csv file, it can take a few minutes depending on your computer.
Then you have a command line: you can type :command:`?` to list available commands. You have for instance:

- `lc` (list connections)
- `ls` (list subflows)
- `plot` 
- ...

`help ls` will return the syntax of the command, i.e. `ls [mptcp.stream]` where mptcp.stream is one of the number appearing 
in `lc` output.

Some more complex commands can be:


.. literalinclude:: /../../tests/batch_commands.txt
   :linenos:

.. _batch-mode:

Batch mode
--------------

Commands are the same as in :ref:`interactive-mode`, they are just saved in a file.

.. code-block:: console

    mptcpanalyzer --batch tests/batch_commands.txt -dddd


.. _oneshot:

One-shot mode
----------------------------------------

Just put your command after your arguments, for instance.

.. code-block:: console

    mptcpanalyzer --load examples/iperf-mptcp-0-0.pcap`


Tips
-----
|prog| is a rather long name so feel free to create an alias for instance :command:`alias mp="mptcpanalyzer"`.

To enable debug informations, run :command:`mptcpanalyzer -dddd`

If you use zsh, you can enable autocompletion via adding to your .zshrc:

.. code-block:: console

    compdef _gnu_generic mptcpanalyzer


Conversion from pcap to csv:
----------------------------------------

|prog| comes bundled with an extra program: *mptcpexporter* can convert a pcap to csv (exporting to sql should be easy).
Run :command:`mptcpexporter -h` to see how it works.


List of available plots
----------------------------------------


.. autoclass:: mptcpanalyzer.cli.MpTcpAnalyzer


.. .. autofunction:: mptcpanalyzer.cli.main


