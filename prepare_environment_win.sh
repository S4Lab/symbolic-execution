fullpreparation=$1
echo "AAA-$1-AAA"
echo "Linking to source files from deploy folder..."
cp -f -l -a -u run_se_win.sh src/* "deploy/"
cd deploy/
rm depends.sh
mv depends_win.sh depends.sh
mkdir -p obj-ia32
cd ..
#if [ ! -f deploy/obj-ia32/libcvc4.dll ]; then
#  cp -l /usr/local/lib/libcvc4.dll deploy/obj-ia32/
#fi

if [ "a$fullpreparation" = "afull" ]; then
	echo "Full preparation..."
	mkdir -p deploy/tmp/se
	#export LD_LIBRARY_PATH=/home/john/twinner/pin-2.14-linux/intel64/runtime
fi
echo "Done."
#bash
