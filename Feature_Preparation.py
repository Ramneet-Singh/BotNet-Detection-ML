import pandas as pd
import numpy as np

# 0,1,3,8,11,14,15,16,18,19
df = pd.read_csv("Data_Features.csv").drop(
    columns=["Unnamed: 0", "Unnamed: 0.1"])
data_test = df.iloc[:250000, np.asarray(
    [0, 1, 2, 3, 5, 10, 13, 16, 17, 18, 20, 21, -1])]
data_test.to_csv("Selected_Features_Test.csv", index=False)
print(data_test.head)
data_train = df.iloc[250000:, np.asarray(
    [0, 1, 2, 3, 5, 10, 13, 16, 17, 18, 20, 21, -1])]
data_train.to_csv("Selected_Features_Train.csv", index=False)
