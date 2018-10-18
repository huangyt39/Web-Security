# -*- coding: utf-8 -*-
from data import *
import pdb

def IPReplace(M):
    res = [0]*64
    for i in range(64):
        res[i] = M[IP[i] - 1]
    return res[:32], res[32:]

def TIterate(L0, R0, key):
    K = GenerateSubkey(key)
    L, R = L0[:], R0[:]
    for i in range(1, 17):
        Lnew = R[:]
        Rnew = [0]*32
        FeistelRes = Feistel(R, K[i])
        for i in range(32):
            Rnew[i] = L[i] ^ FeistelRes[i]
        L, R = Lnew, Rnew
    return L, R

def IPReserveReplace(arr):
    res = arr[:]
    for i in range(64):
        res[i] = arr[IPInverse[i] - 1]
    return res

def GenerateSubkey(key):
    res56 = [[]]
    res48 = [[]]
    subkey = [0] * 56
    for index in range(56):
        subkey[index] = key[PC1[index]]
    C, D = subkey[:28], subkey[28:]
    res56.append(subkey)
    for keycount in range(2, 17):
        C = LS(C, keycount)
        D = LS(D, keycount)
        res56.append(C+D)
    for n in range(1, 17):
        tmp = [0] *48
        for i in range(48):
            # pdb.set_trace()
            tmp[i] = res56[n][PC2[i] - 1]
        res48.append(tmp)
    return res48

def LS(CD, i):
    res = [0]*28
    shift = 2
    if i == 1 or i == 2 or i == 9 or i == 16:
        shift = 1
    for i in range(28):
        res[i] = CD[(i + shift)%28]
    return res

def Feistel(R, k):
    ER, ERK = [0] *48, [0] *48
    restmp = []
    res = [0] *32
    for i in range(48):
        ER[i] = R[E[i] - 1]
    for i in range(48):
        ERK[i] = ER[i] ^ k[i]
    for j in range(8):
        restmp += S(ERK[j*6:j*6+6], j+1)
    # pdb.set_trace()
    for i in range(32):
        res[i] = restmp[P[i] - 1]
    return res

def S(b, i):
    res = [0]*4
    n = b[0]*2 + b[5]
    m = b[1]*8 + b[2]*4 + b[3]*2 + b[4]
    # pdb.set_trace()
    resnum = Sbox[i][n *16 + m]
    m, index = 8, 0
    while m > 0:
        if resnum // m == 1:
            res[index] = 1
            resnum = resnum%m
        m = m//2
        index += 1
    return res

def TIterateReverse(L0, R0, key):
    K = GenerateSubkey(key)
    L, R = L0[:], R0[:]
    for i in range(1, 17):
        Lnew = R[:]
        Rnew = [0]*32
        FeistelRes = Feistel(R, K[17 - i])
        for i in range(32):
            Rnew[i] = L[i] ^ FeistelRes[i]
        L, R = Lnew, Rnew
    return L, R

def DES(arr, key):
    L0, R0 = IPReplace(arr)
    L16, R16 = TIterate(L0, R0, key)
    res = IPReserveReplace(R16 + L16)
    return res

def testDES(C, key):
    R16, L16 = IPReplace(C)
    R0, L0 = TIterateReverse(R16, L16, key)
    res = IPReserveReplace(L0 + R0)
    return res

def Test():
    data = [1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1]
    key = [1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,0,1,1,1,1]
    C = DES(data, key)
    M = testDES(C, key)
    print("M: ", data)
    print("C: ", C)
    print("M: ", M)
    for i in range(64):
        if data[i] != M[i]:
            print("False")
            return
    print("Right")

if __name__ == "__main__":
    Test()