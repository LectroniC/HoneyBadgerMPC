#!/bin/bash
rm /usr/src/HoneyBadgerMPC/.benchmarks/Linux-CPython-3.7-64bit/0002_hbavss_loglin.json
pytest -vs --benchmark-save=hbavss_loglin --benchmark-min-rounds=1 benchmark/test_benchmark_hbavss_loglin.py