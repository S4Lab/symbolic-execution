rawdatafile="./obj-intel64/evaluation/bzip2.license.txt"
rm -f "${rawdatafile}.bz2"
progexec="/bin/bzip2 -k $rawdatafile"
$progexec
