#!/bin/bash
# pytest --benchmark-save=pcl_detailed --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_poly_commit_log.py
pytest --benchmark-save=hbavss_dummy_pcl --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_hbavss_loglin.py
pytest --benchmark-save=hbavss2_only_pcl --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_hbacss2_actual_pcl.py
# pytest --benchmark-save=hbavss_actual_pcl --benchmark-min-rounds=3 --benchmark-warmup-iterations=0 benchmark/test_benchmark_hbavss_actual_loglin.py