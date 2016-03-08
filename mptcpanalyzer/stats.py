# attempt to do some monkey patching
from mptcpanalyzer.command import Command

class DoStats(Command):

    def __init__(self):
        pass

    def do(self, data):
        print("hello world")

    def help(self):
        """
        """
        print("Allow to generate stats")

    def complete(self, text, line, begidx, endidx):
        """
        """
