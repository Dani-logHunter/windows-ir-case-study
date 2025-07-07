# Windows Memory Forensics & Incident Response
Live attack incident response analysis and documentation.

This repository documents a real-world attack simulation and my full investigation process - from detection to memory capture and analysis using volatility and other tools.


This is an attack I recently encountered on my personal machine and I decided to document it for reference. I also have the video proof to show I did the whole process so if you need that, please feel free to request this.

The machine is a low gaming device and as such, there are certain times AVs may need to be temporarily disabled in order to allow certain games work. I believe it was during one of such periods I unfortunately ran into a live malware attack.


CONDITIONS:
ANTI-VIRUS: OFF

WINDOWS DEFENDER: OFF

TAMPER PROTECTION: OFF

DETECTION TOOLS:
EVENT VIEWER
SYSMON
SIGMA
CHAINSAW
POWERSHELL

MEMORY DUMP TOOLS:
Volatility3
WinPmem

I always run a daily scan of my logs just to see how my machine is working behind the scenes. It was due to this that I was able to detect the stealthy malware attack a fews hours after infection (almost 12 hours).


I decided to piece together all the attack pattern and process step by step in order to reconstruct the TTP. The malware bundled a couple of trojans which I was able to detect and collage together in a folder to scan on virus total and potentially check the .exe codes in www.hybrid-analysis.com later to see how they were coded. 

![Detected artifacts](screenshots/virus_total.png)

I ran a clean OS install after documenting this attack as even though I believe I got all the major chain of the attack, I can't guarantee integrity of the OS anymore. Also, a clean install is always great for rock-hard defense.

This may be a long read, please bear with me. Thanks.

The following is my detection/discovery process.

1.
Name/Action: Creation of an Executable by an Executable
Starting_file/Image: Image: C:\Users\User\AppData\Roaming\Microsoft\Telemetry\sihost32.exe  
TargetFilename: C:\Users\User\services32.exe
Time: 8:31
Date: 28\6
This were the first foreign files I encountered that were new to my scan from the previous day. The virus I downloaded dropped these files so I realized it won't be a completely fileless attack. This is a fake sihost, not the real actual shell Infrastructure host file in system32. 
![1](screenshots/01.png)


