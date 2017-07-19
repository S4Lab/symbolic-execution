#!/bin/bash
progname=jm-h264ref
./evalscripts/runner.sh 11100 ./stats/$progname/native.log ./evalscripts/$progname/native.sh
./evalscripts/runner.sh 65 ./stats/$progname/inscount.log ./evalscripts/$progname/inscount.sh loquacious
./evalscripts/runner.sh 32 ./stats/$progname/se.log ./evalscripts/$progname/se.sh loquacious
./evalscripts/runner.sh 32 ./stats/$progname/gil.log ./evalscripts/$progname/gil.sh loquacious
./evalscripts/runner.sh 32 ./stats/$progname/base.log ./evalscripts/$progname/base.sh loquacious
