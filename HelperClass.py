import numpy as np
import Constants as const


class sorthelper:
    keybyte: int = 0
    value: np.uint8 = 0
    distance: int = 0


class doublesorthelper:
    keybyte: np.uint8
    difference: float = 0


class tableentry:
    votes: int = 0
    b: np.uint8 = 0


class session:
    iv = [None]*const.IVBYTES
    keystream = [None]*const.KSBYTES


class attackstate:
    packets_collected = 0
    seen_iv = [0] * const.IVTABLELEN
    sessions_collected: int = 0
    sessions = []
    for i in range(10):
        sessions.append(session())
    table = []
    for i in range(const.MAINKEYBYTES):
        table.append([])
        for j in range(const.LEN_S):
            table[i].append(tableentry())


class rc4state:
    i: np.uint8 = 0
    j: np.uint8 = 0
    s = [0]*const.LEN_S


class network:
    bssid: bytes
    keyid: int
    state: attackstate