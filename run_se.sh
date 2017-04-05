if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
# endpoints are calculated based on caller/one-ins-after-caller
# addresses of the main function from /lib/x86_64-linux-gnu/libc.so.6
# library.
# static (in library) addresses are 21ec3/21ec5
# -taint option argument points to the address of the "testing" string
# -lookup argument is the hex value of the "testing" string
cmd="../../../pin.sh -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -verbose $@ -logfilename out-se -endpoints 0x7fffe169feab,0x7fffe169fead -taint 0x7fffffffe609,0x7fffffffe610 -lookup 74657374696e67 -printstack -- printf \"testing: %x\\n\" 35"
echo "Running \"$cmd\""
sudo su sandbox -c "$cmd"
