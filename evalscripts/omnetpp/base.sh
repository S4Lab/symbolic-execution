if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
SIM_FOLDER="../../../../../omnetpp-5.1/samples/cqn/"
CUR_FOLDER="$(pwd)"
cd "$SIM_FOLDER"
progexec="./cqn -c CQN-A --sim-time-limit=1s"
progname="omnetpp-base"
# endpoints are calculated based on the first-ins-after/one-ins-before
# addresses of calling EnvirBase::startClock/EnvirBase::stopClock
# functions within the Cmdenv::simulate function indicating the main
# simulation loop from the /home/john/omnetpp-5.1/lib/liboppcmdenvd.so
# library.
# static (in library) addresses are d96b/dd81
# grep Instrumenting out-eval-omnetpp-base.log | grep -A8 'mov rax, qword ptr \[rip+0x20856e\]' | grep -A7 -B1 'mov' | grep -A6 -B2 'lea' | grep -A5 -B3 'mov rdi, rax' | grep -A4 -B4 'call.*9c0' | less -R
# -symbols argument points to all allocated cEvent objects (which are passed as arg to the executeEvent function in rsi reg by ins at dc1e static address) each having sizeof(cEvent) bytes
#     cat out-eval-omnetpp-base.log | grep -A2 7ffff6165c1e | grep Expression | gawk -F'Expression\\(' '{ print $2 }' | gawk -F'\\)' '{ print $1 }' | sed 's/\x1B\[[0-9;]*[JKmsu]//g' | xargs echo
args="-pin_memory_range 0x4000000000:0x6000000000 -t $CUR_FOLDER/obj-intel64/SE.Base.so -trace $CUR_FOLDER/tmp/se/trace.dat -memory $CUR_FOLDER/tmp/se/memory.dat -endpoints 0x7ffff616596b,0x7ffff6165d81 -symbols 0x6d1cb0,0x6d1cf8,0x6cfe10,0x6cfe58,0x6c5700,0x6c5748 -verbose $verbose -logfilename $CUR_FOLDER/out-eval-$progname -- $progexec"
sudo su sandbox -c "$CUR_FOLDER/../../../pin.sh $args $@"
