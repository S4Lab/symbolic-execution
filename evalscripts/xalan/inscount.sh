if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
progexec="../../../../../xalan-c-1.11/c/bin/Xalan -o ./xalan-sample.html ./obj-intel64/evaluation/xalan-sample.xml ./obj-intel64/evaluation/xalan-sample.xsl"
rm -f ./xalan-sample.html
progname="xalan-measure"
# endpoints are calculated based on first-ins/ret-ins addresses of
# the XalanTransformer::transform method (the version which is located
# at line 329 of the xalanc/XalanTransformer/XalanTransformer.cpp file)
# located in the /usr/lib/x86_64-linux-gnu/libxalan-c.so.111 library.
# static (in library) addresses are 32c040/32c0b3
# grep Instrumenting out-eval-xalan.log | grep -A6 'push r14' | grep -A5 -B1 'push r13' | grep -A4 -B2 'mov r13, rcx' | grep -A3 -B3 'xor ecx, ecx' | grep -A2 -B4 'push r12' | grep -A1 -B5 'mov r12, rdx' | grep -B6 'push rbp' | less -R
# -symbols argument points to theInputSource arg of transform function (which is passed as first arg to the parseSource function afterwards and is read by instruction at the 3284cf static address) until sizeof(XSLTInputSource) bytes forward
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -measure -endpoints 0x7ffff60d9040,0x7ffff60d90b3 -symbols 0x7fffffffdd00,0x7fffffffdd40 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
