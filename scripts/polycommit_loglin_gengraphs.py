import json
import matplotlib.pyplot as plt
import re


def dehumanize_time(timestr):
    if timestr[-3:] == 'mus':
        return float(timestr[0:-4])/10**6
    if timestr[-2:] == 'ms':
        return float(timestr[0:-3])/10**3


plt.style.use("ggplot")

# Loading
with open(".benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
tvals_provebatch = []
provebatchtimes = []

polytimes = []
polycountvals_provebatch = []

tvals_verifybatch = []
verifybatchtimes = []
for entry in logbenchmarks:
    if entry["name"].startswith("test_benchmark_batch_creation"):
        t = entry["params"]["t"]
        tvals_provebatch.append(str(t))
        provebatchtimes.append(entry["stats"]["mean"] / ((3*t+1)**2))
    if entry["name"].startswith("test_benchmark_prover_dbatch_vary_poly"):
        polycount = entry["params"]["polycount"]
        polycountvals_provebatch.append(str(polycount))
        polytimes.append(entry["stats"]["mean"] / ((3*20+1)*polycount))
    if entry["name"].startswith("test_benchmark_batch_verify"):
        t = entry["params"]["t"]
        tvals_verifybatch.append(str(t))
        verifybatchtimes.append(entry["stats"]["mean"] / (3*t+1))


with open(".benchmarks/Linux-CPython-3.7-64bit/0002_hbavss_loglin.json", "r") as file:
    logdata = file.read().replace("\n", "")
logbenchmarks = json.loads(logdata)["benchmarks"]
hbavss_amt_overhead = []
hbavss_polycommitloglin_overhead = []
tvals_hbavss_amt_benchmark = []
tvals_hbavss_polycommitloglin_benchmark = []

for entry in logbenchmarks:
    # Batch size is t+1
    if entry["name"].startswith("test_hbavss_amt_end_to_end_time"):
        t = entry["params"]["t"]
        hbavss_amt_overhead.append(
            entry["stats"]["mean"] / (t+1)/((3*t+1) ** 2))
        tvals_hbavss_amt_benchmark.append(str(t))
    if entry["name"].startswith("test_hbavss_polycommitloglin_end_to_end_time"):
        t = entry["params"]["t"]
        hbavss_polycommitloglin_overhead.append(
            entry["stats"]["mean"] / (t+1) / ((3*t+1)**2))
        tvals_hbavss_polycommitloglin_benchmark.append(str(t))

width = 0.35
t_pos = [i for i, _ in enumerate(tvals_provebatch)]
#log_pos = [i - width / 2 for i in t_pos]
log_pos = [i for i in t_pos]
#const_pos = [i + width / 2 for i in t_pos]
#Turn units in to ms.
provebatchtimes = [i * 1000.0 for i in provebatchtimes]
plt.bar(log_pos, provebatchtimes, width, label="log")
#plt.bar(const_pos, consttimes, width, label="const")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Generation time per value shared (ms)")
plt.title("PolyCommitLog Prover Benchmarks")

plt.xticks(t_pos, tvals_provebatch)
# plt.yscale("log")
# plt.legend(loc="best")
plt.savefig("pcl/batch_prover", bbox_inches='tight')
plt.clf()

pc_pos = [i for i, _ in enumerate(polycountvals_provebatch)]
plt.bar(pc_pos, polytimes, width, label="log")
#Turn units in to ms.
polytimes = [i * 1000.0 for i in polytimes]
plt.xlabel("Number of polynomials")
plt.ylabel("Amortized Generation time per value shared (ms)")
plt.title("Varying polynomial count while t=20")
plt.xticks(pc_pos, polycountvals_provebatch)
plt.savefig("pcl/vary_polys", bbox_inches='tight')

plt.clf()
t_pos = [i for i, _ in enumerate(tvals_verifybatch)]
#Turn units in to ms.
verifybatchtimes = [i * 1000.0 for i in verifybatchtimes]
plt.bar(t_pos, verifybatchtimes, width, label="log")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Verification time per value shared (ms)")
plt.title("PolyCommitLog Verifier Benchmarks")
plt.xticks(t_pos, tvals_verifybatch)
plt.savefig("pcl/batch_verifier", bbox_inches='tight')


# BEGIN AMT-ONLY BENCHMARKS
plt.clf()
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
    if item == 'avg_verify_usec':
        ver_ind = i
    i += 1

n_arr = [entry[n_ind] for entry in entries]
deal_arr = [int(entry[deal_ind]) / int(entry[n_ind]) /
            10**6 for entry in entries]
ver_arr = [int(entry[ver_ind]) / 10**6 for entry in entries]
n_pos = [i for i, _ in enumerate(n_arr)]

plt.figure(figsize=(15, 6))
#Turn units in to ms.
deal_arr = [i * 1000.0 for i in deal_arr]
plt.bar(n_pos, deal_arr, width)
plt.xlabel("Total players n = 3t+1")
plt.ylabel("Amortized Deal time per recipient (ms)")
plt.title("AMTVSS Dealer Benchmarks")
plt.xticks(n_pos, n_arr)
plt.savefig("pcl/amt_dealer", bbox_inches='tight')

plt.clf()
#Turn units in to ms.
ver_arr = [i * 1000.0 for i in ver_arr]
plt.bar(n_pos, ver_arr, width)
plt.xlabel("Total players n = 3t+1")
plt.ylabel("Verification time (ms)")
plt.title("AMTVSS Verifier Benchmarks")
plt.xticks(n_pos, n_arr)
plt.savefig("pcl/amt_verifier", bbox_inches='tight')

# BEGIN HYBRID BENCHMARKS

plt.clf()
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
    if item == 'avg_verify_usec':
        ver_ind = i
    i += 1

ver_arr = [int(entry[ver_ind]) / 10**6 for entry in entries]
n_arr = [(entry[n_ind]) for entry in entries]

plotting_ver_arr = []
plotting_n_arr = []
for elem in tvals_verifybatch:
    index = n_arr.index(str(int(elem)*3+1))
    plotting_ver_arr.append(ver_arr[index])
    plotting_n_arr.append(n_arr[index])

n_pos = [i for i, _ in enumerate(n_arr)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]
actual_ns_for_tvals_provebatch = [
    str(3 * int(t) + 1) for t in tvals_provebatch]

print(n_arr)
print(actual_ns_for_tvals_provebatch)
plt.bar(pcl_pos, verifybatchtimes, width, label="hb")
#Turn units in to ms.
plotting_ver_arr = [i * 1000.0 for i in plotting_ver_arr]
plt.bar(amt_pos, plotting_ver_arr, width, label="amt")
plt.xlabel("Total recipients (n=3t+1)")
plt.ylabel("Amortized verify time per value shared (ms)")
plt.title("HbAVSS vs AMT Verifier Performance")
plt.xticks(n_pos, plotting_n_arr)
plt.legend(loc="best")
plt.savefig("pcl/pcl vs amt verifier", bbox_inches='tight')


# plt.clf()
# amtdealtimes = []
# for filename in ["amt/t1.txt", "amt/t2.txt", "amt/t5.txt", "amt/t11.txt", "amt/t21.txt", "amt/t33.txt"]:
#     with open(filename, "r") as file:
#         txt = file.read()
#     authrootstime = dehumanize_time(re.search(r"Auth roots-of-unity eval.* per", txt).group()[:-4][26:])
#     authtreetime = dehumanize_time(re.search(r"Auth accum tree.* per", txt).group()[:-4][17:])
#     n = int(re.search(r"n = .* points", txt).group()[:-7][4:])
#     dealtime = (authrootstime + authtreetime) / n
#     amtdealtimes.append(dealtime)

# n_vals = [str(3 * int(t) + 1) for t in tvals_provebatch]
# n_pos = [i for i, _ in enumerate(n_vals)]
# pcl_pos = [i - width / 2 for i in n_pos]
# amt_pos = [i + width / 2 for i in n_pos]
# plt.bar(pcl_pos, provebatchtimes, width, label="hb")
# plt.bar(amt_pos, amtdealtimes, width, label="amt")
# plt.xlabel("Total recipients (n=3t+1)")
# plt.ylabel("Amortized generation time per value shared (seconds)")
# plt.title("HbAVSS vs AMT VSS Dealer Performance")
# plt.xticks(n_pos, n_vals)
# plt.legend(loc="best")
# plt.savefig("pcl/pcl vs amt dealer", bbox_inches='tight')

plt.clf()
deal_arr = [int(entry[deal_ind]) / (10**6.0) / int(n_arr[i])
            for i, entry in enumerate(entries)]
n_pos = [i for i, _ in enumerate(n_arr)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]
n_vals = [str(3 * int(t) + 1) for t in tvals_provebatch]
n_pos = [i for i, _ in enumerate(n_vals)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]

plotting_deal_arr = []
for elem in tvals_provebatch:
    index = n_arr.index(str(int(elem)*3+1))
    plotting_deal_arr.append(deal_arr[index])

plt.bar(pcl_pos, provebatchtimes, width, label="hb")
#Turn units in to ms.
plotting_deal_arr = [i * 1000.0 for i in plotting_deal_arr]
plt.bar(amt_pos, plotting_deal_arr, width, label="amt")
plt.xlabel("Total recipients (n=3t+1)")
plt.ylabel("Amortized generation time per value shared (ms)")
plt.title("HbAVSS vs AMT VSS Dealer Performance")
plt.xticks(n_pos, plotting_n_arr)
plt.legend(loc="best")
plt.savefig("pcl/pcl vs amt dealer", bbox_inches='tight')


plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]
#Turn units in to ms.
hbavss_polycommitloglin_overhead = [i * 1000.0 for i in hbavss_polycommitloglin_overhead]
plt.bar(pcl_pos, hbavss_polycommitloglin_overhead,
        width, label="pcl proof size + hbavss")
#Turn units in to ms.
hbavss_amt_overhead = [i * 1000.0 for i in hbavss_amt_overhead]
plt.bar(amt_pos, hbavss_amt_overhead, width, label="amt proof size + hbavss")
plt.xlabel("Total players (n=3t+1)")
plt.ylabel("Amortized end-to-end time (ms)")
plt.title("Size-match fake proofs for HbAVSS end-to-end time")
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.savefig("pcl/amt_pcl_non_faulty_avss_overhead", bbox_inches='tight')


# Deadling + Verification Time only
plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]

pcl_vssr_pos = [i + width / 2 for i in n_pos]
amt_vssr_pos = [i - width / 2 for i in n_pos]

hbavss_polycommitloglin_e2e = []
hbavss_amt_e2e = []
vssr_polycommitloglin_e2e = []
vssr_amt_e2e = []

for i, _ in enumerate(n_vals):
    pcl_dpv = provebatchtimes[i] + verifybatchtimes[i]
    amt_dpv = plotting_deal_arr[i] + plotting_ver_arr[i]
    vssr_polycommitloglin_e2e.append(pcl_dpv)
    vssr_amt_e2e.append(amt_dpv)

plt.bar(pcl_vssr_pos, vssr_polycommitloglin_e2e, width, label="pcl")
plt.bar(amt_vssr_pos, vssr_amt_e2e, width, label="amt")
plt.xlabel("Total players (n=3t+1)")
plt.ylabel("Amortized end-to-end time (ms)")
plt.title("Dealing + Verification Time ")
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.savefig("pcl/non_faulty_avss_dpv", bbox_inches='tight')


# Amortized total end-to-end time
plt.clf()
n_vals = [str(3 * int(t) + 1) for t in tvals_hbavss_amt_benchmark]
n_pos = [i for i, _ in enumerate(n_vals)]
pcl_pos = [i - width / 2 for i in n_pos]
amt_pos = [i + width / 2 for i in n_pos]


plt.bar(pcl_pos, vssr_polycommitloglin_e2e, width, label="pcl verification + dealing")
plt.bar(amt_pos, vssr_amt_e2e, width, label="amt verification + dealing")
plt.bar(pcl_pos, hbavss_polycommitloglin_overhead, width, label="pcl hbavss overhead",
        bottom=vssr_polycommitloglin_e2e)
plt.bar(amt_pos, hbavss_amt_overhead, width, label="amt hbavss overhead",
        bottom=vssr_amt_e2e)

plt.xlabel("Total players (n=3t+1)")
plt.ylabel("Amortized end-to-end time (ms)")
plt.title("HbAVSS end-to-end time")
plt.xticks(n_pos, n_vals)
plt.legend(loc="best")
plt.savefig("pcl/hbavss_e2e", bbox_inches='tight')
