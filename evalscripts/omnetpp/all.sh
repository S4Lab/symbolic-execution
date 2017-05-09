#!/bin/bash
progname=omnetpp
./evalscripts/runner.sh 1000 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 50 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh loquacious
./evalscripts/runner.sh 62 ./stats/$progname/se.log ./evalscripts/$progname/se.sh loquacious
