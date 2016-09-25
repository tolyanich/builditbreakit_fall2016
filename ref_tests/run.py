#!/usr/bin/python

import json
import os
import subprocess
import sys
import tempfile

user = 'ubuntu'

if len(sys.argv) != 3:
	print( "usage: ./run.py <server> <test>")
	exit( 1)

serverFile = os.path.abspath( sys.argv[1])
testFile = sys.argv[2]
graderFile = './grader'

f = open( testFile, 'r')
test = json.loads( f.read())
f.close()

o = {'input': test, 'type': 'build', 'target': serverFile, 'client_user': user}

f = tempfile.NamedTemporaryFile( delete=False)
f.write( json.dumps( o))
tmp = f.name
f.close()

# print( json.dumps( o))
subprocess.call( [graderFile,tmp])


