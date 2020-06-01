#!/bin/bash
#rm /usr/src/HoneyBadgerMPC/.benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json
pytest --benchmark-save=pclog --benchmark-min-rounds=1 benchmark/test_benchmark_poly_commit_log.py
#rm /usr/src/HoneyBadgerMPC/.benchmarks/Linux-CPython-3.7-64bit/0001_hbavss_loglin.json
pytest -vs --benchmark-save=hbavss_amt --benchmark-min-rounds=1 benchmark/test_benchmark_hbavss_loglin.py::test_hbavss_amt_end_to_end_time
pytest -vs --benchmark-save=hbavss_pcl --benchmark-min-rounds=1 benchmark/test_benchmark_hbavss_loglin.py::test_hbavss_polycommitloglin_end_to_end_time
pytest -vs --benchmark-save=hbavss_worst --benchmark-min-rounds=1 benchmark/test_benchmark_hbavss_loglin.py::test_hbavss_polycommitloglin_end_to_end_time_worst_case
