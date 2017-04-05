#!/bin/bash
progname=bzip2
./evalscripts/runner.sh 30100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 200 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh info
./evalscripts/runner.sh 150 ./stats/$progname/twintool.log ./evalscripts/$progname/se.sh info
