#!/usr/bin/env python3
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib.cbook as cbook


data = {
    "Name": ['Sara', 'John', 'Mark', 'Peter', 'Kate'],
    "Count": [2, 1, 15, 12, 5],
    "Score": [2, 4, 7, 8, 7]
}

df = pd.DataFrame(data)
print(df)

labels = ['Scores']

data = df['Score'].repeat(df['Count']).tolist()
print (data)
# compute the boxplot stats
stats = cbook.boxplot_stats(data, labels=labels, bootstrap=10000)

print(['stats :', stats])

fs = 10  # fontsize

fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(6, 6), sharey=True)
axes.bxp(stats)
axes.set_title('Boxplot', fontsize=fs)

plt.show()
