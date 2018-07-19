#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
import seaborn as sns

dataSet = pd.read_csv('CVE_Cleaned.csv',
                      warn_bad_lines=True, 
                      error_bad_lines=False,
                      delimiter=';', decimal = ',')


""" ---- Number of CVEs discovered by year ---- """

discYear = dataSet['discoveredYear']
plt.title('Number of CVEs discovered by year',{'size':20, 'family':'monospace'})
plt.xlabel('Discovered Year')
plt.ylabel('Count')
discYear.value_counts().plot(kind='bar',
                     color='b',
                     figsize=[10,10]).invert_xaxis()
plt.show()


""" ---- Number of products in the dataSetbase each year ---- """

numProduct = dataSet.groupby('discoveredYear')['product_name'].nunique()
plt.title('Number of products discovered by year',{'size':20, 'family':'monospace'})
plt.xlabel('Discovered Year')
plt.ylabel('Number of Products')
numProduct.plot(kind='line',figsize=[10,10])
plt.show()


""" ---- Top 15 CVE by Vendor ---- """

countVendor = dataSet['vendor_name'].value_counts()
plt.title('Top 15 CVEs found by Vendor',{'size':20, 'family':'monospace'})
plt.xlabel('Count')
plt.ylabel('Vendor Name')
countVendor.head(15).plot(kind='barh',figsize=[10,10]).invert_yaxis()
plt.show()


""" ---- Top 5 OS comparison ---- """ 

selectedOS = dataSet[dataSet.product_name.isin(['windows_10','iphone_os','linux_kernel','android','mac_os_x'])]
plt.title('Top 5 OSs Comparison',{'size':20, 'family':'monospace'})
selectedOS['product_name'].value_counts().plot(kind='pie',figsize=[10,10],autopct='%.2f')
plt.show()


""" ---- CVEs Found by Year ---- """

cveDescCount = dataSet.groupby('discoveredYear')['CWE_Description'].value_counts().unstack().fillna(0)
cveDescCount.tail(10).plot(kind='line',figsize=[10,10],legend=None)
plt.title('Top CVEs found by Year',{'size':20, 'family':'monospace'})
plt.xlabel('Discovered Year')
plt.ylabel('Number of CVEs Found')
#plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
plt.show()


""" ---- Exploitability Vs. Impact Score by year ---- """

avgExploitScr = dataSet.groupby('discoveredYear')['V2_exploitabilityScore'].mean()
avgImpactScr = dataSet.groupby('discoveredYear')['V2_impactScore'].mean()
plt.figure(figsize= (10, 10))
plt.title('Exploitability Vs. Impact Score by year',{'size':20, 'family':'monospace'})
plt.xlabel('Discovered Year')
plt.ylabel('Avg Score')
plt.plot(avgExploitScr, color='blue', label='Exploitabitity Score')
plt.plot(avgImpactScr, color='red', label='Impact Score')
plt.legend()
plt.show()


""" ---- Average Base Score by Year ---- """

avgBaseScr = dataSet.groupby('discoveredYear')['V2_baseScore'].mean()
avgBaseScrTotal = dataSet['V2_baseScore'].mean()
plt.figure(figsize= (10, 10))
plt.title('Average Base Score by year',{'size':20, 'family':'monospace'})
plt.xlabel('Discovered Year')
plt.ylabel('Avg Base Score')
plt.plot(avgBaseScr, label='Avg Base Score')
plt.axhline(y=avgBaseScrTotal, color='green', linestyle='--', label='Avg Base Score Total')
plt.legend()
plt.show()


""" ---- CVEs by Companies and Products ---- """ 

microsoft = dataSet[dataSet.vendor_name.isin(['microsoft'])]
x1 = microsoft['product_name'].value_counts()
x1_percent = (x1[x1>100]*100)/x1[x1>100].sum()

apple = dataSet[dataSet.vendor_name.isin(['apple'])]
x2 = apple['product_name'].value_counts()
x2_percent = (x2[x2>100]*100)/x2[x2>100].sum()

google = dataSet[dataSet.vendor_name.isin(['google'])]
x3 = google['product_name'].value_counts()
x3_percent = (x3[x3>100]*100)/x3[x3>100].sum()

adobe = dataSet[dataSet.vendor_name.isin(['adobe'])]
x4 = adobe['product_name'].value_counts()
x4_percent = (x4[x4>100]*100)/x4[x4>100].sum()

oracle = dataSet[dataSet.vendor_name.isin(['oracle'])]
x5 = oracle['product_name'].value_counts()
x5_percent = (x5[x5>100]*100)/x5[x5>100].sum()

df1 = x1_percent.to_frame().T.rename(index={'product_name': 'microsoft'})
df2 = x2_percent.to_frame().T.rename(index={'product_name': 'apple'})
df3 = x3_percent.to_frame().T.rename(index={'product_name': 'google'})
df4 = x4_percent.to_frame().T.rename(index={'product_name': 'adobe'})
df5 = x5_percent.to_frame().T.rename(index={'product_name': 'oracle'})


pd.concat(dict(df1 = df1, df2 = df2, df3 = df3, df4 = df4, df5 = df5),
          axis = 0,sort=True).plot(kind="barh", stacked=True,figsize=[10,10],colormap=('tab20c'))
plt.title('CVEs by Companies and Products',{'size':20, 'family':'monospace'})
plt.xlabel('% of Product')
plt.ylabel('Vendor Name')
plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
plt.show()



""" ---- correlation Exploitability & Impact Score ---- """

X = dataSet[['V2_exploitabilityScore', 'V2_impactScore']].astype(np.float)

y = dataSet['V2_impactScore'].astype(np.float)

pd.plotting.scatter_matrix(X, alpha = 0.5, figsize = (10,10), diagonal = 'kde',marker = 'o')
plt.title('correlation Exploitability & Impact Score',{'size':20, 'family':'monospace'})
plt.show()


# test

#X = dataSet[['V2_exploitabilityScore']]
#y = dataSet['discoveredYear']
#
#from sklearn.model_selection import train_test_split
#X_train, X_test, y_train, y_test = train_test_split(X,y,test_size = 0.01)
#
#from sklearn.linear_model import LinearRegression
#
#lr = LinearRegression()
#
##lr.fit(X_train, y_train)
#
#plt.figure(figsize= (10, 10))
#plt.scatter(y_train, X_train, color = 'blue',alpha=0.5)
#plt.scatter(y_test, X_test, color = 'green',alpha=0.5)
#plt.show()








