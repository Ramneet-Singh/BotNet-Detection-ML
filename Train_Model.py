import lightgbm as lg
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np

df = pd.read_csv('Selected_Features_Train.csv', chunksize=15000)
clf = None
params = {'boosting': 'gbdt',
          'objective': 'binary',
          'learning_rate': 0.01,
          'num_leaves': 31,
          'is_unbalance': True,
          'verbosity': 100,
          'bagging_freq': 5,
          'bagging_fraction': 0.8}

for data in df:
    X = np.asarray(data.iloc[:, 2:-1])
    Y = np.asarray(data.iloc[:, -1])
    X_train, X_cv, Y_train, Y_cv = train_test_split(
        X, Y, test_size=0.333, random_state=1)
    clf = lg.train(params=params, train_set=lg.Dataset(X_train, Y_train), num_boost_round=2,
                   init_model=clf, valid_sets=lg.Dataset(X_cv, Y_cv), keep_training_booster=True)

del df

df = pd.read_csv('Selected_Features_Test.csv')
X_test = np.asarray(df.iloc[:, 2:-1])
Y_test = np.asarray(df.iloc[:, -1])
pred_prob = clf.predict(X_test)

pred = pred_prob >= 0.5
acc = accuracy_score(Y_test, pred)
prec = precision_score(Y_test, pred)
rec = recall_score(Y_test, pred)
f1 = f1_score(Y_test, pred)

print('Accuracy = ', acc)
print('Precision = ', prec)
print('Recall = ', rec)
print('F1 = ', f1)

clf.save_model('Model_LightGBM.txt')
