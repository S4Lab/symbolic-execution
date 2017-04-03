if [ "a$@" = "a" ]; then echo "No Argument!"; exit; fi
# endpoints are calculated based on caller/one-ins-after-caller
# addresses of the main function from /lib/x86_64-linux-gnu/libc.so.6
# library.
# static (in library) addresses are 21ec3/21ec5
cmd="../../../pin.sh -t ./obj-intel64/SE.so -trace tmp/se/trace.dat -memory tmp/se/memory.dat -verbose $@ -logfilename out-se -endpoints 0x7fffe169aeab,0x7fffe169aead -- /bin/echo test second third"
echo "Running \"$cmd\""
sudo su sandbox -c "$cmd"
