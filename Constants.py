ARP_HEADER = bytes.fromhex("AAAA030000000806")
ARP_REQUEST = bytes.fromhex("0001080006040001")
ARP_RESPONSE = bytes.fromhex("0001080006040002")
LEN_S = 256
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
IVBYTES = 3
KSBYTES = 16
TESTBYTES = 6
MAINKEYBYTES = 13

# number of keys to test
KEYLIMIT = 1000000

# (2^24)/8, max number of IVs in bytes
IVTABLELEN = 2097152