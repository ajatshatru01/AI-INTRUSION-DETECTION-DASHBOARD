import numpy as np

def clean_df(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)
    return df
