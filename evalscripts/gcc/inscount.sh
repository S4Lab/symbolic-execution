verbose="$1"
shift
basename="gcc.fibonacci"
# the srcfile is generated using gcc -E from the corresponding .c file
srcfile="./obj-intel64/evaluation/${basename}.i"
outfile="${srcfile/.i/.s}"
rm -f "${outfile}"
#progexec="/usr/bin/gcc $srcfile -o ${outfile}"
# the gcc internally calls cc1 which is the actual compiler
# the gcc acts as a wrapper here
# the following command is extracted from a gcc run using strace
progexec="/usr/lib/gcc/x86_64-linux-gnu/4.8/cc1 -fpreprocessed $srcfile -quiet -dumpbase ${basename}.i -mtune=generic -march=x86-64 -auxbase ${basename} -fstack-protector -Wformat -Wformat-security -O0 -o ${outfile}"
progname="gcc-measure"
# endpoints are calculated from the caller/one-ins-after-the-caller
# addresses of the c_parse_file function within the
# /usr/lib/gcc/x86_64-linux-gnu/4.8/cc1 binary.
# in binary (static) addresses are 597030/597035
# -taint argument points to the main function source code in the .i input file (int main...)
args="-pin_memory_range 0xd000000000:0xe000000000 -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -measure -endpoints 0x597030,0x597035 -taint 0x13e9b5d,0x13e9c5a -printstack -verbose $verbose -logfilename out-eval-$progname -- $progexec"
sudo su sandbox -c "../../../pin.sh $args $@"
