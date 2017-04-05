#!/bin/bash
num="$1"
shift
statsfile="$1"
shift
progexec="$@"
echo "runner script: num=$num | stats=$statsfile | prog={$progexec}"
for ((i = 1; i <= $num; i++)); do
  echo "runner script: i=$i / num=$num"
  start=$(date +%s.%N)
  $progexec
  dur=$(echo "$(date +%s.%N) - $start" | bc)
  printf "%.6f\n" $dur >> $statsfile
done
echo "runner script: done!"
