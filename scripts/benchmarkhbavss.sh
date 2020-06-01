#!/bin/bash
rm /usr/src/HoneyBadgerMPC/.benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json
pytest --benchmark-save=pclog --benchmark-min-rounds=5 benchmark/test_benchmark_poly_commit_log.py
rm /usr/src/HoneyBadgerMPC/.benchmarks/Linux-CPython-3.7-64bit/0001_hbavss_loglin.json
pytest --benchmark-save=hbavss_loglin --benchmark-min-rounds=5 benchmark/test_benchmark_hbavss_loglin.py
