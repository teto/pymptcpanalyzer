from .command import Command

import logging


"""
While in mptcpanalyzer sources, one can do getLogger(__name__) to retrieve a
(sub)logger, your plugin can be in another package and as such, you have to name
the logger explicitly with mptcpanalyzer.**
"""
log = logging.getLogger("mptcpanalyzer")

class CommandExample(Command):
    """
    This is just an example of how to write a plugin that will be automatically
    loaded by mptcpanalyzer.

    """
    def do(self, data):
        """
        :param data: This is the line passed by the user to the interpreter
        """
        print("You wrote: %s" % data)

    def help(self):
        """
        Message printed when the author writes
        """
        print("Prints 'Hello world !' followed by the user message")

    def complete(self, text, line, begidx, endidx):
        """
        To provide autocompletion
        """
        pass
