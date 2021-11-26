# 4010-WEP-PTW
## Overview
This project aims to implement an attack on WEP security, PTW attack. The main file to use is `ptw.py`. The rest are there to better organize the codes.
Usage requires packet capture file using other programs as described [below](#acquiring-arp-packets).

Based on [aircrack-ptw<sup>1](#references)

Written for CZ4010 Project

## Background
WEP (Wired Equivalent Privacy) was a security algorithm for wireless networks. It was introduced in 1997 and uses the stream cipher [RC4](https://en.wikipedia.org/wiki/RC4 "RC4 Wikipedia")
for encryption. The earliest attack to RC4, and by extension, WEP, was published in 2001 in the form of [FMS attack](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack).

This project implements a more recently published attack, the [PTW attack<sup>2](#references), which requires fewer packets than FMS attack to get the key, although with some limitations.

## Files
- `ptw.py`: The main file to run
- `KeyCompute.py`: Contains functions that actually computes the key
- `HelperClass.py`: Helper class definitions
- `Constants.py`: Constant values

## Requirements

- Python3
- ~30000 or more ARP packets with unique IVs

Python Libraries:
- numpy
- scapy

## Usage
Make sure all required Python packages are installed using:

```
pip install -r requirements.txt
```
Start the attack using:

```
python ptw.py <your capture file>
```

## Output
Example output:
```
Found key with 40-bit length
['0x1f', '0x1f', '0x1f', '0x1f', '0x1f']
```

Means a 40-bit key is found, in hexadecimal format:
```
1F:1F:1F:1F:1F
```


## Acquiring ARP packets
A detailed writeup to make sure you have the proper hardware and drivers to capture packets is available [here.](https://www.aircrack-ng.org/doku.php?id=getting_started)

Detailed method to capture the required WEP packets to use in this attack are available 
[here](https://www.aircrack-ng.org/doku.php?id=arp-request_reinjection) or [here.](https://www.javatpoint.com/arp-request-replay-attack)

A working sample of WEP capture file used in the example above is available [here.](https://download.aircrack-ng.org/ptw.cap)

## Limitations
- Only supports ARP packets.
- Only supports WEP with shared key setup
- Only supports 40-bit and 104-bit keys

## References
- [1] [aircrack-ptw](https://web.archive.org/web/20110610115301/http://www.cdc.informatik.tu-darmstadt.de/aircrack-ptw/)
- [2] [Tews, Erik & Weinmann, Ralf-Philipp & Pyshkin, Andrei. (2007). Breaking 104 Bit WEP in less than 60 seconds. IACR Cryptology ePrint Archive. 2007. 188-202. 10.1007/978-3-540-77535-5_14.](https://eprint.iacr.org/2007/120.pdf) 
- [Beck, Martin & Tews, Erik. (2008). Practical attacks against WEP and WPA. IACR Cryptology ePrint Archive. 2008. 472. 10.1145/1514274.1514286.](https://eprint.iacr.org/2008/472.pdf)

