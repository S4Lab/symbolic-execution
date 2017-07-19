if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
rm -f tmp/se/leakybucketparam.cfg
progexec="../../../../../jm-h264ref/bin/lencod.exe -d ./obj-intel64/evaluation/jm-h264ref-encoder.cfg"
progname="jm-h264ref-base"
# endpoints are calculated based on caller/one-ins-after-caller
# addresses of the encode_sequence function (changed to be non-static)
# from the ~/jm-h264ref/bin/lencod.exe binary file.
# static (in library) addresses are 40338c/403391
# -symbols argument points to the p_Vid arg of encode_sequence function (in lencod/src/lencod.c file; set by ins at 45a5dd static address) until sizeof(VideoParameters) bytes forward
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.Base.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x40338c,0x403391 -symbols 0x780040,0x787bb8 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
