verbose="$1"
shift
rawdatafile="./obj-intel64/evaluation/bzip2.license.txt"
rm -f "${rawdatafile}.bz2"
progexec="/bin/bzip2 -k $rawdatafile"
progname="bzip2-measure"
# endpoints are calculated from the caller/one-ins-after-the-caller
# addresses of the BZ2_bzCompress function from the 
# /lib/x86_64-linux-gnu/libbz2.so.1.0 library.
# in library (static) addresses are c0e8/c0ed
# -symbols argument points to the "This program..." input string
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -measure -endpoints 0x7ffff61a30e8,0x7ffff61a30ed -symbols 0x7fffffffcd6d,0x7fffffffcd79 -printstack -lookup 546869732070726f6772616d -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
