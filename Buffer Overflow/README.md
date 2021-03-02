# Buffer Overflow

[1. Fuzz the Application](#fuzz-the-application)
  
[2. Replicating the Crash and Controlling EIP](#replicating-the-crash-and-controlling-eip)

[3. Find Bad Characters](#finding-bad-characters)

4. Find the Jumpoint 

5. Generate the Payload

6. Add Padding to Allow Shellcode to Unpack

7. Exploit

Set a working directory for Mona from teh Immunity Debugger. Run the following command from the command line in Immunity Debugger

<code>!mona config -set workingfolder c:\mona\%p</code>

![alt-text](src/Mona_Command.png)

## Fuzz the Application

Launch Immunity Debugger as Administrator, and use the "File -> Open" command to bring up the vulnerable application. Notice that this does not run the aplication, it still needs to be executed.  

![alt-text](src/Paused_State.png)

Click the red play button at the top of the window to execute the file

![alt-text](src/Running_State.png)

Use the program located [here](fuzzer.py) to fuzz the application. It will send strings to the application incrementing by 500 characters each time until the app crashes or it reaches a string of length 3000.

<code>python fuzzer.py</code>

![alt-text](src/Fuzzing.png)

Make note of when the script stops/the application crashes and the length of the string that caused the crash.

## Replicating the Crash and Controlling EIP

Use the program located [here](exploit.py) (This is the base script, we will modify it as needed with the information we acquire during the assessment of the application)

Note: that the prefix variable will need to be changed to account for whatever initial option the applications takes.

We then need to generate a string of the length of the string that crashed the application + 400. In our case, the application crashed after the 2000 string, so we will generate our string to be size 2400

<code>/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2400</code>

Copy this output to the "payload" field in the exploit.py script

Restart the application in the Immunity Debugger and run the exploit.py script.

<code>python exploit.py</code>

The app should crash again, run the following command in Immunity Debugger:

<code>!mona findmsp -distance 2400</code>

Note that we use the same length as the pattern we created earlier.

Mona will display a window with some output in the form of:

> EIP contains normal pattern: ... (offset XXXX)

We will then need to update our exploit.py script and set the offset varialbe to the value of the offset. 

Set the retn variable to "BBBB"

Restart the application in Immunity Debugger and rerun the exploit.py script.

We should see the EIP register is now 42424242 (BBBB)

## Finding Bad Characters

