import json
import matplotlib.pyplot as plt
import re


import os
if not os.path.exists('graphs'):
    os.makedirs('graphs')

def dehumanize_time(timestr):
    if timestr[-3:] == 'mus': return float(timestr[0:-4])/10**6
    if timestr[-2:] == 'ms': return float(timestr[0:-3])/10**3


plt.style.use("ggplot")

with open("../.benchmarks/Linux-CPython-3.7-64bit/0001_pclog.json", "r") as file:
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

#with open("../.benchmarks/Linux-CPython-3.7-64bit/0002_const.json", "r") as file:
#    constdata = file.read().replace("\n", "")
#constbenchmarks = json.loads(constdata)["benchmarks"]
#consttimes = []
#for entry in constbenchmarks:
#    if entry["name"].startswith("test_benchmark_create_wit"):
#        consttimes.append(entry["stats"]["mean"] * (3 * entry["params"]["t"] + 1))

width = 0.35
t_pos = [i for i, _ in enumerate(tvals_provebatch)]
#log_pos = [i - width / 2 for i in t_pos]
log_pos = [i for i in t_pos]
#const_pos = [i + width / 2 for i in t_pos]
plt.bar(log_pos, provebatchtimes, width, label="log")
#plt.bar(const_pos, consttimes, width, label="const")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Generation time per proof (seconds)")
plt.title("PolyCommitLog Prover Benchmarks")

plt.xticks(t_pos, tvals_provebatch)
#plt.yscale("log")
#plt.legend(loc="best")
plt.savefig("graphs/batch_prover", bbox_inches='tight')
plt.clf()

pc_pos = [i for i, _ in enumerate(polycountvals_provebatch)]
plt.bar(pc_pos, polytimes, width, label="log")
plt.xlabel("Number of polynomials")
plt.ylabel("Amortized Generation time per proof (seconds)")
plt.title("Varying polynomial count while t=20")
plt.xticks(pc_pos, polycountvals_provebatch)
plt.savefig("graphs/vary_polys", bbox_inches='tight')

plt.clf()
t_pos = [i for i, _ in enumerate(tvals_verifybatch)]
plt.bar(t_pos, verifybatchtimes, width, label="log")
plt.xlabel("Threshold (t)")
plt.ylabel("Amortized Verification time per proof (seconds)")
plt.title("PolyCommitLog Verifier Benchmarks")
plt.xticks(t_pos, tvals_verifybatch)
plt.savefig("graphs/batch_verifier", bbox_inches='tight')