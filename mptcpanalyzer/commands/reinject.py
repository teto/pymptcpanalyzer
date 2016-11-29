
import command
import argparse

class Reinjections(command.Command):
    def do(self, data):
        """
        Must be implemented
        """
    

    def help(self, data):
        """
        Must be implemented
        """
        print("Detect reinjections and tell if they were useful or not")

    def complete(self, text, line, begidx, endidx):
        """
        to help complete
        """
        pass
