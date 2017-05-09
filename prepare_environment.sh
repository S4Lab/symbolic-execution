fullpreparation=$1

echo "Linking to source files from deploy folder..."
cp -f -l -a -u run_se.sh src/* "deploy/"
cp -f -l -a -u -r evalscripts "deploy/"
cp -f -a -u -r "test/evaluation" "deploy/obj-intel64/"
ln -f -s "./obj-intel64/evaluation/sjeng.rc" "deploy/sjeng.rc"

if [ "a$fullpreparation" = "afull" ]; then
	echo "Full preparation..."
	ptracescope=$(cat /proc/sys/kernel/yama/ptrace_scope)
	aslrstate=$(cat /proc/sys/kernel/randomize_va_space)
	if [ ! "$ptracescope$aslrstate" = "00" ]; then
		if [ ! "$ptracescope" = "0" ]; then
			echo "Disabling yama ptrace protection for parent-child debugging..."
			echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope > /dev/null
		fi
		if [ ! "$aslrstate" = "0" ]; then
			echo "Disabling ASLR for multiple executions..."
			echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
		fi
		echo "Disabling swap for memory loop safety..."
		sudo swapoff -a
		sudo -k
	fi
	sudo rm -rf 'deploy/tmp/se'
	mkdir 'deploy/tmp/se'
	filenames="log.dat data.txt" # these are for the jm-h264ref test program
	filenames+=" bug.lrn losers.lrn standard.lrn suicide.lrn" # these are for the sjeng test program
	for filename in $filenames; do
		touch "deploy/$filename"
		sudo chgrp sandbox "deploy/$filename"
		chmod 664 "deploy/$filename"
	done
	sudo chgrp sandbox 'deploy/obj-intel64/evaluation' 'deploy/tmp/se'
	chmod 775 'deploy/obj-intel64/evaluation' 'deploy/tmp/se'
	sudo su sandbox -c 'cp deploy/obj-intel64/evaluation/symbols.dat deploy/tmp/se/'
	export LD_LIBRARY_PATH=/home/john/twinner/pin-2.14-linux/intel64/runtime
fi
echo "Done."
bash
