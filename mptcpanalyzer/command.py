import abc
import six

@six.add_metaclass(abc.ABCMeta)
class Command:
    @abc.abstractmethod
    def do(self, data):
        """
        Must be implemented
        """

    @abc.abstractmethod
    def help(self, data):
        """
        Must be implemented
        """

    def complete(self, text, line, begidx, endidx):
        """
        to help complete
        """
