if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
args="-pin_memory_range 0x40000000:0x60000000 -t ./obj-ia32/SE.dll -trace tmp/se/trace.dat -memory tmp/se/memory.dat -verbose $@ -logfilename out-se -endpoints 0x21ec3,0x21ec5 -- /bin/echo test second third"
echo "Running \"../../../pin.exe $args\""
../../../pin.exe $args
