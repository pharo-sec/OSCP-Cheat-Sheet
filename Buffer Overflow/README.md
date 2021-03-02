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

Set a working directory for Mona from teh Immunity Debugger. Run the following command from the command line in Immunity Debugger

<code>!mona config -set workingfolder c:\mona\%p</code>

### Fuzz the Application

Launch Immunity Debugger as Administrator, and use the "File -> Open" command to bring up the vulnerable application. Notice that this does not run the aplication, it still needs to be executed. Click the red play button at the top of the window to execute the file. 

Use the program located [here](fuzzer.py) to fuzz the application. It will send strings to the application incrementing by 500 characters each time until the app crashes or it reaches a string of length 3000.

Make note of when the script stops/the application crashes and the length of the string that caused the crash.


