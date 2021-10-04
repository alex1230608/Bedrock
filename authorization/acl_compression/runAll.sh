#!/bin/bash

rs=($(seq 50 110 100))
as=($(seq 1.1 0.1 1.9))
as+=("-1" "-2" "-3")

rm log.txt
for r in "${rs[@]}"; do
    for a in "${as[@]}"; do
        echo ================================================================= >> log.txt
        echo python3 range_to_entriesCount.py -a $a -r $r >> log.txt
        python3 range_to_entriesCount.py -a $a -r $r >> log.txt 2>&1
    done
done
echo finished!
