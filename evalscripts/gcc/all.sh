#!/bin/bash
progname=gcc
./evalscripts/runner.sh 10100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 50 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh info
./evalscripts/runner.sh 50 ./stats/$progname/twintool.log ./evalscripts/$progname/se.sh info
