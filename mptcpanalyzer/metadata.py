"""
"""


class Metadata:

    def __init__(self):
        self.version = 0
        self.options = 0

    def write(self, fd):
        fd.write("# options:")

    def read(self, fd):
        pass

