# The program is obtained from the https://github.com/justinhj/astar-algorithm-cpp repository
if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
progexec="../../../../../astar-algorithm-cpp-master/cpp/8puzzle 123065478"
progname="astar-8puzzle-base"
# endpoints are calculated based on caller/one-ins-after-caller
# addresses of the main function from /lib/x86_64-linux-gnu/libc.so.6
# library.
# static (in library) addresses are 21f43/21f45
# grep Instrumenting out-eval-astar-8puzzle-base.log | grep -A6 'mov rax' | grep -A5 -B1 'mov rsi' | grep -A4 -B2 'mov edi' | grep -A3 -B3 'mov rdx' | grep -A2 -B4 'mov rax' | grep -A1 -B5 'call rax' | less -R
# -symbols argument points to the "123065478" puzzle argument
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.Base.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x7ffff5aaef43,0x7ffff5aaef45 -symbols 0x7fffffffe57c,0x7fffffffe585 -printstack -lookup 313233303635343738 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
