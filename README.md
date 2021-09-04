# AstroBWT

AstroBWT is a proof-of-work (PoW) algorithm based on Burrows-Wheeler transform (BWT).

Developed and used by the DERO Project for Mobile (arm)/CPU/GPU Mining on their mainnet since March 2020.

## How it works
- Step 1: calculate SHA3 of input data
- Step 2: expand data using Salsa20
- Step 3: calculate BWT of step 2
- Step 4: calculate SHA3 of BWT data
- Step 5: calculate size of stage2 with random number based on step 4
- Step 6: expand data using Salsa20 with size of step 5
- Step 7: Calculate BWT of data from step 6
- Step 8: calculate SHA3 of BWT data from step 7

For more information, visit the official implementation [here](https://github.com/deroproject/astrobwt).

## Benchmarks
 Users can report their benchmarks on the following website: [here](https://benchmark.dero.network/).