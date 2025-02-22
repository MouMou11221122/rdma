#!/bin/bash

client_num=2

make --no-print-directory -C .. clean
make --no-print-directory -C .. TEST_MULTI_STREAM=$client_num

rm -rf ../log/*

for (( i=1; i<=client_num; i++ ))
do
    ../client > ../log/client${i}.log 2>&1 &
done
