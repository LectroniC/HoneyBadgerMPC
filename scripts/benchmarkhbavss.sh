#!/bin/bash
rm ../.benchmarks/Linux-CPython-3.7-64bit/0001_hbavss_loglin.json
cd ..
pytest --benchmark-save=hbavss_loglin benchmark/test_benchmark_hbavss_loglin.py