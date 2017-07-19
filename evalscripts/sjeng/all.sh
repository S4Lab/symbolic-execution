#!/bin/bash
progname=sjeng
./evalscripts/runner.sh 20100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 100 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh debug
./evalscripts/runner.sh 100 ./stats/$progname/se.log ./evalscripts/$progname/se.sh debug
./evalscripts/runner.sh 100 ./stats/$progname/gil.log ./evalscripts/$progname/gil.sh debug
./evalscripts/runner.sh 100 ./stats/$progname/base.log ./evalscripts/$progname/base.sh debug
