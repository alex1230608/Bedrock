import random
from .data import *

def pair(yax):
    pair0 = []
    for i in range(len(yax)-1):
        pair0.append([yax[i], yax[i+1]])
    return pair0

def locatey(y, pair0):
    for i in range(len(pair0)):
        if y >= pair0[i][0] and y < pair0[i][1]:
            no = i
            break
    return i

## Indiada data, pair sequential 2 datas into 1 sections
pairx_idiada = pair(x_idiada) 
pairy_idiada = pair(y_idiada)

## Arctur data, pair sequential 2 datas into 1 sections
pairx_arctur = pair(x_arctur)
pairy_arctur = pair(y_arctur)

## Osdi fig 10 Twem data, pair sequential 2 datas into 1 sections
pairx_osdi = pair(x_osdi_twem)
pairy_osdi = pair(y_osdi_twem)

def linear_getx(y, pairx, pairy):
    i = locatey(y, pairy)
    x = (y-pairy[i][0]) * (pairx[i][1] - pairx[i][0])/(pairy[i][1] - pairy[i][0]) + pairx[i][0]
    return 10 ** x
## The function to call    
def idiada_f():
    y = random.uniform(0,1)
    return linear_getx(y, pairx_idiada, pairy_idiada) * (10**6)
def arctur_f():
    y = random.uniform(0,1)
    return linear_getx(y, pairx_arctur, pairy_arctur) * (10**6)
def osdi_twem_f():
    y = random.uniform(0,1)
    return linear_getx(y, pairx_osdi, pairy_osdi)

def cdf(x, plot=True, *args, **kwargs):
    x, y = sorted(x), np.arange(len(x)) / len(x)
    return plt.plot(x, y, *args, **kwargs) if plot else (x, y)

def main():
    a = []
    b = []
    c = []
    for i in range(100000):
        a.append(idiada_f())
    a = np.log10(a)
    
    for i in range(100000):
        b.append(arctur_f())
    b = np.log10(b)
    
    for i in range(100000):
        c.append(osdi_twem_f())
    c = np.log10(c)

    # cdf(a)
    # cdf(b)
    # cdf(c)
