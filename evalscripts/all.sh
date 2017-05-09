#!/bin/bash
for progname in perl astar bzip2 gcc gnugo hmmer jm-h264ref omnetpp grover sjeng xalan; do
  echo "============================ Starting $progname evaluation..."
  mkdir -p "./stats/$progname"
  ./evalscripts/$progname/all.sh
  echo "============================ Evaluation of $progname is done."
done
