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

# Number of CVEs discovered by year

discYear = dataSet['discoveredYear']
plt.title('Number of CVEs discovered by year')
plt.xlabel('Discovered Year')
plt.ylabel('Count')
discYear.value_counts().plot(kind='bar', 
    color='b', figsize=[10,10]).invert_xaxis()
plt.show()


# Number of products in the dataSetbase each year

numProduct = dataSet.groupby('discoveredYear')['product_name'].nunique()
plt.title('Number of products discovered by year')
plt.xlabel('Discovered Year')
plt.ylabel('Number of Products')
numProduct.plot(kind='line', figsize=[10,10])
plt.show()


# Top 15 CVE by Vendor

countVendor = dataSet['vendor_name'].value_counts()
plt.title('Top 15 CVEs found by Vendor')
plt.xlabel('Count')
plt.ylabel('Vendor Name')
countVendor.head(15).plot(kind='barh', figsize=[10,10]).invert_yaxis()
plt.show()


# Top 5 OS comparison 

selectedOS = dataSet[dataSet.product_name.isin(['windows_10','iphone_os','linux_kernel','android','mac_os_x'])]
plt.title('Top 5 OSs Comparison')
selectedOS['product_name'].value_counts().plot(kind='pie', figsize=[10,10])
plt.show()


# CVEs Found by Year

cveDescCount = dataSet.groupby('discoveredYear')['CWE_Description'].value_counts().unstack().fillna(0)
cveDescCount.tail(10).plot(kind='line', figsize=[10,10],legend=None)
plt.title('Top CVEs found by Year')
plt.xlabel('Discovered Year')
plt.ylabel('Number of CVEs Found')
plt.show()


# Exploitability Vs. Impact Score by year 

avgExploitScr = (dataSet.groupby('discoveredYear')['V2_exploitabilityScore'].sum())/dataSet.groupby('discoveredYear')['V2_exploitabilityScore'].count()
avgImpactScr = (dataSet.groupby('discoveredYear')['V2_impactScore'].sum())/dataSet.groupby('discoveredYear')['V2_impactScore'].count()
plt.figure(figsize= (10, 10))
plt.title('Exploitability Vs. Impact Score by year')
plt.xlabel('Discovered Year')
plt.ylabel('Avg Score')
plt.plot(avgExploitScr, color='blue', label='Exploitabitity Score')
plt.plot(avgImpactScr, color='red',label='Impact Score')
plt.legend()
plt.show()


# Average Base Score by Year

sumBaseScr = dataSet.groupby('discoveredYear')['V2_baseScore'].sum()
numBaseScr = dataSet.groupby('discoveredYear')['V2_baseScore'].count()
avgBaseScr = sumBaseScr/numBaseScr
avgTotal = sumBaseScr.sum()/numBaseScr.sum()
plt.figure(figsize= (10, 10))
plt.title('Average Base Score by year')
plt.xlabel('Discovered Year')
plt.ylabel('Avg Base Score')
plt.plot(avgBaseScr)
plt.axhline(y=avgTotal, color='green', linestyle='--')
#plt.plot(avgTotal,color='green',linestyle='--')
#plt.legend()
plt.show()


# CVEs by Companies and Products 

selectedVendor = dataSet[dataSet.vendor_name.isin(['microsoft','apple','google','adobe','oracle','ibm','cisco'])]
#y = (selectedOS2['product_name'].value_counts()*100)/selectedOS2['product_name'].value_counts().sum()


#
X = dataSet[['V2_exploitabilityScore', 'V2_impactScore']].astype(np.float)

y = dataSet['V2_impactScore'].astype(np.float)

pd.scatter_matrix(X, alpha = 0.3, figsize = (10,10), diagonal = 'kde')



