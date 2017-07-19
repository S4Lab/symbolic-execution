if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
verbose="$1"
shift
infile="./obj-intel64/evaluation/sjeng.in"
progexec="../../../../../Sjeng-Free-11.2/sjeng"
progname="sjeng-gil"
# endpoints are calculated based on the caller/one-ins-after-caller
# addresses of the think function of the ~/Sjeng-Free-11.2/sjeng
# binary file which is called after the "go" input command.
# static (in library) addresses are 4021af/4021b4
# -symbols argument points to the "int board[144]" array (which has a fixed address defined in sjeng.c file)
args="-pin_memory_range 0x4000000000:0x6000000000 -t ./obj-intel64/SE.GIL.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -endpoints 0x4021af,0x4021b4 -symbols 0x925b00,0x925d40 -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@ < $infile"
