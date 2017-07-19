#!/bin/bash
progname=bzip2
./evalscripts/runner.sh 30100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 200 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh debug
./evalscripts/runner.sh 150 ./stats/$progname/se.log ./evalscripts/$progname/se.sh debug
./evalscripts/runner.sh 150 ./stats/$progname/gil.log ./evalscripts/$progname/gil.sh debug
./evalscripts/runner.sh 150 ./stats/$progname/base.log ./evalscripts/$progname/base.sh debug
