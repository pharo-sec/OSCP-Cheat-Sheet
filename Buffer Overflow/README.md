# Buffer Overflow

## High Level Overview

  1. Fuzz the application
  
  2. Recreate the crash with targeted payloads

  3. Determine the exact offset and test the return address

  4. Find bad characters

  5. Find the jumpoint 

  6. Generate the payload

  7. Add some padding to allow the shellcode to unpack

  8. Exploit
