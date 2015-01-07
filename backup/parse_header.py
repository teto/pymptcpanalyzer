#!/usr/bin/env python
import sys
with open(sys.argv[1]) as f
   for line in f:
       if (line.strip()):
           print (line.split().index(sys.argv[2])+1)
           sys.exit(0)