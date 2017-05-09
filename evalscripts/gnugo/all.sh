#!/bin/bash
progname=gnugo
./evalscripts/runner.sh 20100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 50 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh debug
./evalscripts/runner.sh 50 ./stats/$progname/se.log ./evalscripts/$progname/se.sh debug
