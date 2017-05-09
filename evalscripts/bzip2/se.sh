verbose="$1"
shift
rawdatafile="./obj-intel64/evaluation/bzip2.license.txt"
rm -f "${rawdatafile}.bz2"
progexec="/bin/bzip2 -k $rawdatafile"
progname="bzip2"
# endpoints are calculated from the caller/one-ins-after-the-caller
# addresses of the BZ2_bzCompress function from the 
# /lib/x86_64-linux-gnu/libbz2.so.1.0 library.
# in library (static) addresses are c0e8/c0ed
# grep Instrumenting out-eval-bzip2.log | grep -A6 'test rdi' | grep -A5 -B1 '1b' | grep -A4 -B2 'push rbx' | less -R # one ins back...
# -taint argument points to the "This program..." input string
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x7ffff61a20e8,0x7ffff61a20ed -taint 0x7fffffffcd8d,0x7fffffffcd99 -printstack -lookup 546869732070726f6772616d -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
