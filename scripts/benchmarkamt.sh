#!/bin/bash
sh generate-qsdh-params.sh crs 500
BenchVSS crs 2 257 amt 5 5 5 vssresults.csv
BenchAMT crs 2 4 10 2> t1.txt
BenchAMT crs 3 7 10 2> t2.txt
BenchAMT crs 6 16 10 2> t5.txt
BenchAMT crs 12 34 10 2> t11.txt
BenchAMT crs 22 64 10 2> t21.txt
BenchAMT crs 34 100 10 2> t33.txt