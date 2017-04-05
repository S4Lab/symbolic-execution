basename="gcc.fibonacci"
# the srcfile is generated using gcc -E from the corresponding .c file
srcfile="./obj-intel64/evaluation/${basename}.i"
outfile="${srcfile/.i/.s}"
rm -f "${outfile}"
#progexec="/usr/bin/gcc $srcfile -o ${outfile}"
# the gcc internally calls cc1 which is the actual compiler
# the gcc acts as a wrapper here
# the following command is extracted from a gcc run using strace
progexec="/usr/lib/gcc/x86_64-linux-gnu/4.8/cc1 -fpreprocessed $srcfile -quiet -dumpbase ${basename}.i -mtune=generic -march=x86-64 -auxbase ${basename} -fstack-protector -Wformat -Wformat-security -o ${outfile}"
$progexec
