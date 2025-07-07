# Lessons Learned - Live Incident Response & Forensics

This document captures key lessons, takeaways, and reflections from handling and analyzing a real - life cyber incident using various blue team tools and techniques.

----------


## Technical Lessons

- ** Log Integrity is Key **
 
  The '.evtx' log files are always crucial to investigation. Without the logs, Blue teams are running blind so I believe log protection should be the first priority of any endpoint or server. Having tampered with or deleted logs will make investigation a lot harder.
  
  Back up of logs files are extremely crucial


- ** AVs aren't enough **
  
  A clever attacker could easily bypass Heuristic scans by renaming persistent scripts to things Avs are familiar with. My defender did flag a few things, but it missed a whole bunch of them as well.


  - **Volatility is incredible **
   
    Being able to dig into dumped images is extremely powerful.


## Operational Lessons

  - ** Isolate first, investigate second **
    
    Cutting off my machine from the local network early prevented a possible lateral movement or establish a convenient command & control server for the attacker.

  - ** staying calm during Real attacks **

     Panic wastes time and allows crucial events be missed. A methodical response made things manageable after spotting presence of adversary. This is why constant monitoring is crucial. Automation is great but I love and prefer to manually go through my daily logs.

    We never know what is lurking.

    - ** It is important to document **
     Sharing this work on Github helps track progress and showcase my interest, dedication and ability in joining the fight agaisnt cyber criminals.



## Personal Growth

   - Now I understand how real incidents feel: confusing, fast, and stressful - but also deeply insightful and educational.
 
   - I believe I gained confidence in using tools like sysmon, sigma, volatility in real contects.
 
   - I learned to structure findings clearly for others to review.
 
   - I feel more like a true SOC analyst with hands - on understanding - not only theory.
 
   - I believe the real growth sets in when you respond under pressure, learn through failure, and keep moving forward. 

   - We never stop learning. There are still so many attacks in the wild and I stay up to date with reading on MITRE ATT&CK, reading cyber attack news from all over the world and just learning how to better using advanced tools for protection.
