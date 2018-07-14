#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
import seaborn as sns

data = pd.read_csv('CVE_Cleaned.csv',
                      warn_bad_lines=True, 
                      error_bad_lines=False,
                      delimiter=';')

# Number of CVEs discovered by year

discYear = data['discoveredYear']
plt.title('Number of CVEs discovered by year')
plt.xlabel('Discovered Year')
plt.ylabel('Count')
discYear.value_counts().plot(kind='bar', 
    color='b', figsize=[10,10]).invert_xaxis()
plt.show()


# Number of products in the database each year

numProduct = data.groupby('discoveredYear')['product_name'].nunique()
plt.title('Number of products discovered by year')
plt.xlabel('Discovered Year')
plt.ylabel('Number of Products')
numProduct.plot(kind='line', figsize=[10,10])
plt.show()


# Top 15 CVE by Vendor

countVendor = data['vendor_name'].value_counts()
plt.title('Top 15 CVEs found by Vendor')
plt.xlabel('Count')
plt.ylabel('Vendor Name')
countVendor.head(15).plot(kind='barh', figsize=[10,10]).invert_yaxis()
plt.show()


# Top 5 OS comparison 

selectedOS = data[data.product_name.isin(['windows_10','iphone_os','linux_kernel','android','mac_os_x'])]
plt.title('Top 5 OS Comparison')
selectedOS['product_name'].value_counts().plot(kind='pie', figsize=[10,10])
plt.show()


# Exploitability Vs. Impact Score by year 

#exploitScr = data.groupby('discoveredYear')['V2_exploitabilityScore'].sum()
#impactScr = data.groupby('discoveredYear')['V2_impactScore']
#plt.title('Exploitability Vs. Impact Score by year')
#plt.xlabel('Discovered Year')
#plt.ylabel('Avg Score')


# CVEs Found by Year

cveDescCount = data.groupby('discoveredYear')['CWE_Description'].value_counts().unstack().fillna(0)
cveDescCount.tail(10).plot(kind='line', figsize=[10,10],legend=None)
plt.title('Top CVEs found by Year')
plt.xlabel('Discovered Year')
plt.ylabel('Number of CVEs Found')
plt.show()


