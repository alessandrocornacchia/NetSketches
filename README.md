# Net-Sketches

## Introduction

This project includes the P4 implementation of Net-Sketches: a system of network disaggregated sketches for fast and accurate heavy-hitter detection. A reference to the full paper will be available soon, please refer to the short paper [A Traffic-Aware Perspective on Network Disaggregated Sketches](https://ieeexplore.ieee.org/document/9501234) at MedComNet 2020.

## Instructions
The code runs on Mininet using the bmv2 software switch as P4 target. To install the required dependency and set up the environment, please refer to
the instructions in the official p4lang [tutorial](https://github.com/p4lang/tutorials/) repository.
This will install a VM with graphical desktop and all the software pre-installed.
First, login with user `p4` password `p4`. Then, in your shell, run the following instructions:
   ```bash
   cd tutorials/exercises/
   git clone https://github.com/alessandrocornacchia/NetSketches.git
   cd NetSketches
   make run
   ```
You should now see a Mininet command prompt. Open two terminals for the host `h1` and
`h2`, respectively:
  ```bash
  mininet> xterm h1 h2
  ```
Each host includes a small Scapy client and server. In
`h2`'s xterm, start the server script:
  ```bash
  ./receive.py
  ```
In `h1`'s xterm, send an empty message to `h2`:
  ```bash
  ./send.py 10.0.2.2
  ```
  and verify that the console in `h2` shows the new NetSketch header.
  This header contains:
  1. `bitmask` : a bit set to 1 indicates to the switch in the corrsponding position along the flow path to count the packet.
  2. `counter` : allows a switch to know its position along the flow path
