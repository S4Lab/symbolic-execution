#!/bin/bash
progname=astar
./evalscripts/runner.sh 22100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 500 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh debug
./evalscripts/runner.sh 500 ./stats/$progname/se.log ./evalscripts/$progname/se.sh debug
