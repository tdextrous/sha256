# SHA-256
Some fun with SHA-256

Trying to start with a high level (Python) implementation of SHA-256, checking against FIPS test vectors and pre-existing libraries (mainly OpenSSL), then go to a working FPGA implementation on programmable logic of a Zybo Z7-10 board.

## Status
 - Python, C code functionally accurate, matching all FIPS test vectors.
 - RTL code functionally accurate (matching single message block test vector)
 - Meets timing at around 140 MHz (estimated from WNS on 250 MHz timing report).

## TODO
 - Pipeline the RTL more to help meet timing at 250 MHz on Zybo board.
 - Store large hash values in BRAM to reduce utilization.
 - May increase SHA round duration from 2 clock cycles to 3 clock cycles to meet timing.
 - Use existing C model to verify RTL with SystemVerilog DPI.
 - Code cleanup.
