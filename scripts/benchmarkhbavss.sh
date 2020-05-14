#!/bin/bash
cd ..
rm hbavss_benchmark_data.txt
pytest --benchmark-save=pclog benchmark/test_benchmark_hbavss_loglin.py