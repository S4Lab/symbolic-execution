if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
progexec="../../../../../hmmer-3.1b2/src/hmmsearch ./obj-intel64/evaluation/hmmer.hmm ./obj-intel64/evaluation/hmmer-sample.seq"
progname="hmmsearch"
# endpoints are calculated based on the caller/one-ins-after-caller
# addresses of the p7_Pipeline function of
# the ~/hmmer-3.1b2/src/hmmsearch binary file which is compiled from
# the v3.1b2 configured to use serial execution.
# static (in binary) addresses are 404d68/404d6d
# -taint argument points to the sq argument of p7_Pipeline function (which is set by ins at 415564 static address) until sizeof(ESL_SQ) bytes forward
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x404d68,0x404d6d -taint 0x6f1e00,0x6f1ed8 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
