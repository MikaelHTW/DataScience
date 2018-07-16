# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

#dataSet = pd.read_csv("D:\\bereinigt.csv", encoding='ISO-8859-1', delimiter = ';', decimal = ',', thousands = ',')
dataSet = pd.read_csv("D:\\CVE_Cleaned.csv", encoding='ISO-8859-1', delimiter = ';', decimal = ',', thousands = '.')

discoveredYear = dataSet[['discoveredYear']]
discoveredYear_total = discoveredYear['discoveredYear'].value_counts()

vendornames = dataSet[['vendor_name']]
vendornames_total = vendornames['vendor_name'].value_counts()

productnames = dataSet[['product_name']]
productnames_total = productnames['product_name'].value_counts()

bar1 = productnames_total[:30].plot(kind='bar')
bar2 = vendornames_total[:30].plot(kind='bar')



#dataSet_c = dataSet[dataSet['V2_exploitabilityScore'] != '?']
#dataSet_c.loc[:, 'V2_exploitabilityScore'] = dataSet_c['V2_exploitabilityScore']





X = dataSet[['V2_exploitabilityScore', 'V2_impactScore']].astype(np.float)

y = dataSet['V2_impactScore'].astype(np.float)

plt.matshow(X.corr())
pd.scatter_matrix(X, alpha = 0.3, figsize = (14,8), diagonal = 'kde');
sns.pairplot(X)
#rs = np.random.RandomState(0)
#df = X(rs.rand(10, 10))
#corr = df.corr()
#corr.style.background_gradient()