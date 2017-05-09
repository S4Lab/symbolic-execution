verbose="$1"
shift
progexec="/usr/bin/perl ./obj-intel64/evaluation/perl.run.sh"
progname="perl"
# endpoints are calculated from the entry/ret addresses of
# the perl_run function from the /usr/lib/libperl.so.5.18 library.
# in library (static) addresses are 4a4c0/4a6ca
# grep Instrumenting out-eval-perl.log | grep -A6 'push r14' | grep -A5 -B1 'mov rax' | grep -A4 -B2 'xor esi, esi' | grep -A3 -B3 'push rbx' | grep -A2 -B4 'sub rsp, 0xf8' | grep -A1 -B5 'mov rax' | less -R
# -taint argument points to the "hello world" string
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x7ffff60674c0,7ffff60676ca -taint 0x62ac10,0x62ac1b -printstack -lookup 68656c6c6f20776f726c64 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
