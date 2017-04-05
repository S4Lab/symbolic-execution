verbose="$1"
shift
progexec="/usr/bin/perl ./obj-intel64/evaluation/perl.run.sh"
progname="perl-measure"
# endpoints are calculated from the entry/ret addresses of
# the perl_run function from the /usr/lib/libperl.so.5.18 library.
# in library (static) addresses are 4a4c0/4a6ca
# -taint argument points to the "hello world" string
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x7ffff606c4c0,0x7ffff606c6ca -taint 0x6330b0,0x6330bb -measure -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
