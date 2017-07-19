if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
progexec="../../../../../gnugo-3.8/interface/gnugo -l ./obj-intel64/evaluation/gnugo.sgf --score estimate"
progname="gnugo-base"
# endpoints are calculated based on the first-ins/ret-ins of the
# compute_scores function from the ~/gnugo-3.8/interface/gnugo binary
# file which is compiled from the v3.8 where float data types have
# been replaced with int to make it similar to the SPEC cpu int test.
# static (in binary) addresses are 424fb0/4250e3
# -symbols argument points to the &move_influence (which is set by ins at 424ff3 static address) until sizeof(struct influence_data) bytes forward
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-intel64/SE.Base.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x424fb0,0x4250e3 -symbols 0xf484a0,0xf4f788 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
