#!/bin/bash

client_num=2

make --no-print-directory -C .. clean
make --no-print-directory -C .. TEST_MULTI_STREAM=$client_num
