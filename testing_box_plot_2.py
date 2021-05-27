#!/usr/bin/env python3
import pandas as pd
import seaborn as sns

import matplotlib.pyplot as plt

data = {
    "Name": ['Sara', 'John', 'Mark', 'Peter', 'Kate'],
    "Count": [20, 10, 5, 2, 5],
    "Score": [2, 4, 7, 8, 7]
}
df = pd.DataFrame(data)

def reindex_df(df, weight_col):
    """expand the dataframe to prepare for resampling
    result is 1 row per count per sample"""
    df = df.reindex(df.index.repeat(df[weight_col]))
    df.reset_index(drop=True, inplace=True)
    return(df)

df = reindex_df(df, weight_col = 'Count')

sns.boxplot(x='Name', y='Score', data=df)
plt.show()
