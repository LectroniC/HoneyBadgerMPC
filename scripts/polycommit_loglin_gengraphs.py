import json
import matplotlib.pyplot as plt
import re
import math


def dehumanize_time(timestr):
    if timestr[-3:] == 'mus':
        return float(timestr[0:-4])/10**6
    if timestr[-2:] == 'ms':
        return float(timestr[0:-3])/10**3

# Larger graph for detailed profiling
# plt.figure(figsize=(17, 3))
plt.figure(figsize=(10, 3))
axis_label_size = 12
title_size = 12
color1 = "#e84a27"
color2 = "#13294b"
tick_fontsize = 12

# Loading
with open(".benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
tvals_provebatch = []
provebatchtimes = []
provebatchtimes_yerr = []

polytimes = []
polycountvals_provebatch = []

tvals_verifybatch = []
verifybatchtimes = []
verifybatchtimes_yerr = []
for entry in logbenchmarks:
    if entry["name"].startswith("test_benchmark_batch_creation"):
        t = entry["params"]["t"]
        tvals_provebatch.append(str(t))
        provebatchtimes.append(entry["stats"]["mean"] / ((3*t+1)**2))
        provebatchtimes_yerr.append(entry["stats"]["stddev"]*2/((3*t+1)**2))
    if entry["name"].startswith("test_benchmark_prover_dbatch_vary_poly"):
        polycount = entry["params"]["polycount"]
        polycountvals_provebatch.append(str(polycount))
        polytimes.append(entry["stats"]["mean"] / ((3*20+1)*polycount))
    if entry["name"].startswith("test_benchmark_batch_verify"):
        t = entry["params"]["t"]
        tvals_verifybatch.append(str(t))
        verifybatchtimes.append(entry["stats"]["mean"] / (3*t+1))
        verifybatchtimes_yerr.append(entry["stats"]["stddev"]*2/(3*t+1))


provebatchtimes = [i * 1000.0 for i in provebatchtimes]
verifybatchtimes = [i * 1000.0 for i in verifybatchtimes]
polytimes = [i * 1000.0 for i in polytimes]

hbavss_amt_overhead = []
hbavss_polycommitloglin_overhead = []
tvals_hbavss_amt_benchmark = []
tvals_hbavss_polycommitloglin_benchmark = []

with open(".benchmarks/Linux-CPython-3.7-64bit/0003_hbavss_pcl.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    # Batch size is t+1
    if entry["name"].startswith("test_hbavss_polycommitloglin_end_to_end_time"):
        t = entry["params"]["t"]
        hbavss_polycommitloglin_overhead.append(
            entry["stats"]["mean"] / ((3*t+1)**2))
        tvals_hbavss_polycommitloglin_benchmark.append(str(t))

hbavss_polycommitloglin_overhead = [
    i * 1000.0 for i in hbavss_polycommitloglin_overhead]

with open(".benchmarks/Linux-CPython-3.7-64bit/0002_hbavss_amt.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    # Batch size is t+1
    if entry["name"].startswith("test_hbavss_amt_end_to_end_time"):
        t = entry["params"]["t"]
        hbavss_amt_overhead.append(
            entry["stats"]["mean"] / ((3*t+1) ** 2))
        tvals_hbavss_amt_benchmark.append(str(t))

hbavss_amt_overhead = [i * 1000.0 for i in hbavss_amt_overhead]

hbavss_pcl_implicate_case_overhead = []
tvals_hbavss_pcl_implicate_case_benchmark = []
with open(".benchmarks/Linux-CPython-3.7-64bit/0005_hbavss_implicate_pcl.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    # Batch size is t+1
    if entry["name"].startswith("test_hbavss_end_to_end_time_implicate_case_pcl"):
        t = entry["params"]["t"]
        hbavss_pcl_implicate_case_overhead.append(
            entry["stats"]["mean"] / ((3*t+1) ** 2))
        tvals_hbavss_pcl_implicate_case_benchmark.append(str(t))


hbavss_amt_implicate_case_overhead = []
tvals_hbavss_amt_implicate_case_benchmark = []
with open(".benchmarks/Linux-CPython-3.7-64bit/0004_hbavss_implicate_amt.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
for entry in logbenchmarks:
    # Batch size is t+1
    if entry["name"].startswith("test_hbavss_end_to_end_time_implicate_case_amt"):
        t = entry["params"]["t"]
        hbavss_amt_implicate_case_overhead.append(
            entry["stats"]["mean"] / ((3*t+1) ** 2))
        tvals_hbavss_amt_implicate_case_benchmark.append(str(t))

hbavss_pcl_implicate_case_overhead = [
    i*1000.0 for i in hbavss_pcl_implicate_case_overhead]
hbavss_amt_implicate_case_overhead = [
    i*1000.0 for i in hbavss_amt_implicate_case_overhead]

pc_pos = [i for i, _ in enumerate(polycountvals_provebatch)]

with open("amt/vssresults.csv", "r") as file:
    lines = file.readlines()
entries = []
for line in lines[1:]:
    entry = line.split(',')
    entries.append(entry)
header = lines[0].split(',')
i = 0
for item in header:
    if item == 't':
        t_ind = i
    if item == 'n':
        n_ind = i
    if item == 'avg_deal_usec':
        deal_ind = i
    if item == 'stddev_deal':
        deal_stddev_ind = i
    if item == 'avg_verify_usec':
        ver_ind = i
    if item == 'stddev_verify':
        ver_stddev_ind = i
    if item == 'avg_reconstr_wc_usec':
        amt_reconstr_wc_usec = i
    if item == 'stddev_reconstr_wc_usec':
        amt_reconstr_wc_stddev_ind = i
    if item == 'avg_reconstr_bc_usec':
        avg_reconstr_bc_usec = i
    if item == 'stddev_reconstr_bc_usec':
        avg_reconstr_bc_usec_stddev_ind = i
    i += 1

# Units are microseconds
ver_arr = [float(entry[ver_ind]) / (10**3) for entry in entries]
ver_yerr_arr = [float(entry[ver_stddev_ind])*2 / (10**3) for entry in entries]

n_arr = [(entry[n_ind]) for entry in entries]

deal_arr = [float(entry[deal_ind]) / (10**3.0) / int(n_arr[i])
            for i, entry in enumerate(entries)]
deal_yerr_arr = [float(entry[deal_stddev_ind])*2 / (10**3.0) / int(n_arr[i])
                 for i, entry in enumerate(entries)]
amt_reconstr_wc_arr = [
    float(entry[amt_reconstr_wc_usec]) / (10**3) for entry in entries]
amt_reconstr_bc_arr = [
    float(entry[avg_reconstr_bc_usec]) / (10**3) for entry in entries]

plotting_ver_arr = []
plotting_n_arr = []
plotting_reconstr_wc_arr = []
plotting_reconstr_bc_arr = []
plotting_ver_yerr_arr = []
for elem in tvals_verifybatch:
    index = n_arr.index(str(int(elem)*3+1))
    plotting_ver_arr.append(ver_arr[index])
    plotting_n_arr.append(n_arr[index])
    plotting_ver_yerr_arr.append(ver_yerr_arr[index])
    plotting_reconstr_wc_arr.append(amt_reconstr_wc_arr[index])
    plotting_reconstr_bc_arr.append(amt_reconstr_bc_arr[index])

n_vals = [str(3 * int(t) + 1) for t in tvals_provebatch]
n_pos = [i for i, _ in enumerate(n_vals)]

plt.clf()
plt.plot(verifybatchtimes, linestyle='-', marker='o',
         color=color1, label="PolyCommitHB")
plt.plot(plotting_ver_arr, linestyle='-', marker='o',
         color=color2, label="AMT PC")

#plt.errorbar(plotting_n_arr, verifybatchtimes, yerr=verifybatchtimes_yerr, fmt='none')
#plt.errorbar(plotting_n_arr, plotting_ver_arr, yerr=plotting_ver_yerr_arr, fmt='none')
plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Amortized verify time per proof (ms)", fontsize=axis_label_size)
plt.title("PolyCommitHB vs AMT PC Verification Performance",
          fontsize=title_size)
plt.xticks(n_pos, plotting_n_arr)
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("pcl/pcl_vs_amt_verification.png", bbox_inches='tight')
plt.savefig("pcl/pcl_vs_amt_verification.pdf", bbox_inches='tight')

plotting_deal_arr = []
plotting_deal_yerr_arr = []
for elem in tvals_provebatch:
    index = n_arr.index(str(int(elem)*3+1))
    plotting_deal_arr.append(deal_arr[index])
    plotting_deal_yerr_arr.append(deal_yerr_arr[index])

plt.clf()
plt.plot(provebatchtimes, linestyle='-', marker='o',
         color=color1, label="PolyCommitHB")
plt.plot(plotting_deal_arr, linestyle='-', marker='o',
         color=color2, label="AMT PC")

#plt.errorbar(plotting_n_arr, provebatchtimes, yerr=provebatchtimes_yerr, fmt='none')
#plt.errorbar(plotting_n_arr, plotting_deal_arr, yerr=plotting_deal_yerr_arr, fmt='none')
plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Amortized generation time per proof (ms)",
           fontsize=axis_label_size)
plt.title("PolyCommitHB vs AMT PC Proof Generation", fontsize=title_size)
plt.xticks(n_pos, plotting_n_arr)
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("pcl/pcl_vs_amt_prove_generation.png", bbox_inches='tight')
plt.savefig("pcl/pcl_vs_amt_prove_generation.pdf", bbox_inches='tight')

plt.figure(figsize=(10, 3))

plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]
#pcl_pos = [i - width / 2 for i in n_pos]
#amt_pos = [i + width / 2 for i in n_pos]
# plt.bar(pcl_pos, hbavss_polycommitloglin_overhead,
#         width, label="pcl proof size + hbavss")
# plt.bar(amt_pos, hbavss_amt_overhead, width, label="amt proof size + hbavss")
plt.xlabel("Total players (n=3t+1)")
plt.ylabel("Amortized end-to-end time (ms)")
plt.title("Size-match fake proofs for HbAVSS end-to-end time")
plt.xticks(n_pos, n_vals)
# plt.legend(loc="best")
plt.ylim(0)


plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]
amt_hbavss_implicate_case_runtime_plot_invalid_share = []
amt_hbavss_implicate_case_runtime_plot_valid_share = []
amt_vss_implicate_case_runtime_plot = []
for i, t in enumerate(tvals_hbavss_amt_implicate_case_benchmark):
    amt_hbavss_implicate_case_runtime_plot_valid_share.append(
        hbavss_amt_implicate_case_overhead[i] + plotting_deal_arr[i] +
        plotting_ver_arr[i])
    amt_hbavss_implicate_case_runtime_plot_invalid_share.append(
        hbavss_amt_implicate_case_overhead[i] + plotting_deal_arr[i] +
        plotting_ver_arr[i] + (int(t)+1)*plotting_ver_arr[i])
    amt_vss_implicate_case_runtime_plot.append(
        plotting_reconstr_bc_arr[i] + plotting_deal_arr[i] + plotting_ver_arr[i])
hbavss_pcl_only_related_cost = []
hbavss_amt_only_related_cost = []
hbavss_pcl_sum_cost = []
hbavss_amt_sum_cost = []
for i, t in enumerate(tvals_hbavss_amt_implicate_case_benchmark):
    hbavss_pcl_only_related_cost.append(
        provebatchtimes[i] +
        verifybatchtimes[i] + (int(t)+1)*verifybatchtimes[i])
    hbavss_amt_only_related_cost.append(
        plotting_deal_arr[i] +
        plotting_ver_arr[i] + (int(t)+1)*plotting_ver_arr[i])
    hbavss_pcl_sum_cost.append(
        hbavss_pcl_only_related_cost[-1]+hbavss_pcl_implicate_case_overhead[i])
    hbavss_amt_sum_cost.append(
        hbavss_amt_only_related_cost[-1]+hbavss_amt_implicate_case_overhead[i])

# plt.plot(hbavss_pcl_only_related_cost,  linestyle='-', marker='v',
#          color=color1, label="PolyCommitHB related costs")
plt.plot(hbavss_pcl_implicate_case_overhead,  linestyle='--', marker='^',
         color=color1, label="PolyCommitHB + hbAVSS protocol costs")
plt.plot(hbavss_pcl_sum_cost, linestyle='-', marker='o',
         color=color1, label="PolyCommitHB + hbAVSS total costs")
# plt.plot(hbavss_amt_only_related_cost,  linestyle='-', marker='v',
#          color=color2, label="AMT PC related costs")
plt.plot(hbavss_amt_implicate_case_overhead,  linestyle='--', marker='^',
         color=color2, label="AMT PC + hbAVSS protocol costs")
plt.plot(hbavss_amt_sum_cost, linestyle='-', marker='o',
         color=color2, label="AMT PC + hbAVSS total costs")

plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Amortized end-to-end time per value shared(ms)",
           fontsize=axis_label_size)
plt.title("PolyCommitHB and AMT PC Instantiating hbAVSS t-implicate Runtime",
          fontsize=title_size)
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("pcl/hbavss_e2e_including_reconstruction.png", bbox_inches='tight')
plt.savefig("pcl/hbavss_e2e_including_reconstruction.pdf", bbox_inches='tight')

# No implicate breakdown:
# Deadling + Verification Time only
plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]

non_faulty_hbavss_polycommitloglin_e2e = []
non_faulty_hbavss_amt_e2e = []
for i, _ in enumerate(n_vals):
    pcl_e2e = provebatchtimes[i] + verifybatchtimes[i] + \
        hbavss_polycommitloglin_overhead[i]
    amt_e2e = plotting_deal_arr[i] + \
        plotting_ver_arr[i] + hbavss_amt_overhead[i]
    non_faulty_hbavss_polycommitloglin_e2e.append(pcl_e2e)
    non_faulty_hbavss_amt_e2e.append(amt_e2e)

plt.plot(hbavss_polycommitloglin_overhead,  linestyle='--', marker='^',
         color=color1, label="PolyCommitHB + hbAVSS protocol costs")
plt.plot(non_faulty_hbavss_polycommitloglin_e2e, linestyle='-', marker='o',
         color=color1, label="PolyCommitHB + hbAVSS total costs")

plt.plot(hbavss_amt_overhead,  linestyle='--', marker='^',
         color=color2, label="AMT PC + hbAVSS protocol costs")
plt.plot(non_faulty_hbavss_amt_e2e, linestyle='-', marker='o',
         color=color2, label="AMT PC + hbAVSS total costs")

plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Amortized time per value shared(ms)",
           fontsize=axis_label_size)
plt.title("PolyCommitHB and AMT PC Instantiating hbAVSS Non-Faulty (No implicate) Runtime",
          fontsize=title_size)
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("pcl/hbavss_e2e_non_faulty.png", bbox_inches='tight')
plt.savefig("pcl/hbavss_e2e_non_faulty.pdf", bbox_inches='tight')

# Protocol cost comparison:
plt.clf()
plt.plot(hbavss_polycommitloglin_overhead,  linestyle='--', marker='^',
         color=color1, label="PolyCommitHB + hbAVSS protocol costs (No implicate)")
plt.plot(hbavss_pcl_implicate_case_overhead, linestyle='-', marker='o',
         color=color1, label="PolyCommitHB + hbAVSS protocol costs (t implicate)")

plt.plot(hbavss_amt_overhead,  linestyle='--', marker='^',
         color=color2, label="AMT PC + hbAVSS protocol costs (No implicate)")
plt.plot(hbavss_amt_implicate_case_overhead, linestyle='-', marker='o',
         color=color2, label="AMT PC + hbAVSS protocol costs (t implicate)")

plt.xlabel("Total players (n=3t+1)", fontsize=axis_label_size)
plt.ylabel("Amortized time per value shared(ms)",
           fontsize=axis_label_size)
plt.title("PolyCommitHB and AMT PC Instantiating hbAVSS Protocol Costs",
          fontsize=title_size)
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.xticks(fontsize=tick_fontsize)
plt.yticks(fontsize=tick_fontsize)
plt.ylim(0)
plt.savefig("pcl/hbavss_e2e_overhead_comparsion.png", bbox_inches='tight')
plt.savefig("pcl/hbavss_e2e_overhead_comparsion.pdf", bbox_inches='tight')