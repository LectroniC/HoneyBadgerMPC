import json
import matplotlib.pyplot as plt
import re

figure, axes = plt.subplots(nrows = 2, ncols = 2, figsize=(9,9))

average_bytes_sent_by_dealer = []
average_bytes_sent_by_others = []
average_commitments_sent_by_dealers = []
average_commitments_sent_by_others = []
section_length = 4
ts = [[] for i in range(section_length)]
with open("hbavss_benchmark_data.txt", "r") as file:
  for num, line in enumerate(file.readlines()):

    if num%section_length == 0:
      average_bytes_sent_by_dealer.append(float(line.split(":")[-1]))
      ts[0].append(int(line.split(":")[1].split("=")[-1]))
    if num%section_length == 1:
      average_bytes_sent_by_others.append(float(line.split(":")[-1]))
      ts[1].append(int(line.split(":")[1].split("=")[-1]))
    if num%section_length == 2:
      average_commitments_sent_by_dealers.append(float(line.split(":")[-1]))
      ts[2].append(int(line.split(":")[1].split("=")[-1]))
    if num%section_length == 3:
      average_commitments_sent_by_others.append(float(line.split(":")[-1]))
      ts[3].append(int(line.split(":")[1].split("=")[-1]))

"""
plt.setp(axes[0,0],xlabel = "Value of t", ylabel="Average bytes sent")
"""

cols = ["Dealer", "Receiver Average"]
rows = ["Average bytes sent","Average commitments sent"]
for ax, col in zip(axes[0], cols):
    ax.set_title(col)

for ax, row in zip(axes[:,0], rows):
    ax.set_ylabel(row, size='large')

for i in range(len(cols)):
  for j in range(len(rows)):
    axes[i,j].set_xlabel("Value of t", size='small')

axes[0,0].plot(ts[0],average_bytes_sent_by_dealer)
axes[0,1].plot(ts[1],average_bytes_sent_by_others)
axes[1,0].plot(ts[2],average_commitments_sent_by_dealers)
axes[1,1].plot(ts[3],average_commitments_sent_by_others)
figure.savefig("hbavss_graphs.pdf")


"""
Average by values shared
"""

figure, axes = plt.subplots(nrows = 2, ncols = 2, figsize=(9,7))
average_bytes_sent_by_dealer = []
average_bytes_sent_by_others = []
average_commitments_sent_by_dealers = []
average_commitments_sent_by_others = []
section_length = 4
ts = [[] for i in range(section_length)]
with open("hbavss_benchmark_data.txt", "r") as file:
  for num, line in enumerate(file.readlines()):
    if num%section_length == 0:
      average_bytes_sent_by_dealer.append(float(line.split(":")[-1]))
      ts[0].append(int(line.split(":")[1].split("=")[-1]))
      average_bytes_sent_by_dealer[-1] = average_bytes_sent_by_dealer[-1]/(ts[0][-1]+1)
    if num%section_length == 1:
      average_bytes_sent_by_others.append(float(line.split(":")[-1]))
      ts[1].append(int(line.split(":")[1].split("=")[-1]))
      average_bytes_sent_by_dealer[-1] = average_bytes_sent_by_dealer[-1]/(ts[1][-1]+1)
    if num%section_length == 2:
      average_commitments_sent_by_dealers.append(float(line.split(":")[-1]))
      ts[2].append(int(line.split(":")[1].split("=")[-1]))
      average_commitments_sent_by_dealers[-1] = average_commitments_sent_by_dealers[-1]/(ts[2][-1]+1)
    if num%section_length == 3:
      average_commitments_sent_by_others.append(float(line.split(":")[-1]))
      ts[3].append(int(line.split(":")[1].split("=")[-1]))
      average_commitments_sent_by_others[-1] = average_commitments_sent_by_dealers[-1]/(ts[3][-1]+1)

cols = ["Dealer", "Receiver Average"]
rows = ["Average bytes sent per value shared","Average commitments sent per value shared"]
for ax, col in zip(axes[0], cols):
    ax.set_title(col)

for ax, row in zip(axes[:,0], rows):
    ax.set_ylabel(row, size='large')

for i in range(len(cols)):
  for j in range(len(rows)):
    axes[i,j].set_xlabel("Value of t", size='small')

axes[0,0].plot(ts[0],average_bytes_sent_by_dealer)
axes[0,1].plot(ts[1],average_bytes_sent_by_others)
axes[1,0].plot(ts[2],average_commitments_sent_by_dealers)
axes[1,1].plot(ts[3],average_commitments_sent_by_others)
figure.savefig("hbavss_graphs_average_by_number_of_value_shared.pdf")