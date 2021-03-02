# Buffer Overflow

## High Level Overview

  1. Fuzz the Application
  
  2. Recreate the Crash with Targeted Payloads

  3. Determine Offset and Test Return Address

  4. Find Bad Characters

  5. Find the Jumpoint 

  6. Generate the Payload

  7. Add Padding to Allow Shellcode to Unpack

  8. Exploit


### Fuzz the Application

Use the program located [here](buffer-overflow/fuzzer.py)
