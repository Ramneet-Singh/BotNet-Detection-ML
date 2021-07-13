from sklearn.feature_selection import RFE, SelectKBest, chi2, SelectFpr
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
import numpy as np

df = pd.read_csv('Train_CV_Data.csv')
X_train = np.asarray(df.loc[:2000000, 'srcPort':'HTTPM4'])
Y_train = np.asarray(df.loc[:2000000, 'malicious'], dtype=np.int32)
print(np.sum(Y_train == 1))

kBest = SelectKBest(chi2, k=12)
kBest.fit(X_train, Y_train)
mask1 = kBest.get_support(indices=True)

fpr = SelectFpr(chi2, alpha=0.0001)
fpr.fit(X_train, Y_train)
mask2 = fpr.get_support(indices=True)

rf = RandomForestClassifier(n_estimators=50)

rfe = RFE(rf, n_features_to_select=12, step=1)
rfe.fit(X_train, Y_train)
mask3 = rfe.get_support(indices=True)

print('K-Best Feat :', mask1)
print('False Positive based :', mask2)
print('RFE based :', mask3)
