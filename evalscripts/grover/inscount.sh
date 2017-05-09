if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
progexec="../../../../../libquantum-1.1.1/grover 15"
progname="grover-measure"
# endpoints are calculated based on caller/one-ins-after-caller
# addresses of the main function from /lib/x86_64-linux-gnu/libc.so.6
# library.
# static (in library) addresses are 21f43/21f45
# grep Instrumenting out-eval-grover.log | grep -A8 'lea rax' | grep -A7 -B1 'mov' | grep -A6 -B2 'mov rax' | grep -A5 -B3 'mov rsi' | grep -A4 -B4 'mov edi' | grep -A3 -B5 'mov rdx' | grep -A2 -B6 'mov rax' | grep -A1 -B7 'call' | less -R
# -taint argument points to the grover cli argument
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -measure -endpoints 0x7ffff58ccf43,0x7ffff58ccf45 -taint 0x7fffffffe5b8,0x7fffffffe5ba -printstack -lookup 3135 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
