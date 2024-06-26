**Windows Memory Forensics Using Linux (Ubuntu)**  

**Overview**  
This project focuses on conducting memory forensics on Windows systems using Linux (specifically Ubuntu) and the Volatility Framework (version 2.6.1). The aim is to retrieve valuable information from memory dumps that can aid forensic investigators in identifying suspicious activities and potential security incidents.

**Tools Used**  
Operating System: Linux (Ubuntu)  
Forensic Framework: Volatility Framework 2.6.1  

**Project Goals**  
The primary goal of this project is to perform an in-depth analysis of a memory dump (G13 Dump) to uncover valuable forensic information. This includes identifying suspicious processes, hidden processes, malicious activities, and potential security threats.  

**Installation**  
Installing Volatility Framework on Ubuntu   

Update your package list:  
  sudo apt update
  
 Install dependencies:  
  sudo apt install -y git python3 python3-pip python3-dev
  
Clone the Volatility repository:  
  git clone https://github.com/volatilityfoundation/volatility.git
  
Navigate to the Volatility directory:  
  cd volatility
  
Install Python dependencies:  
  sudo pip3 install -r requirements.txt
  
Install Volatility:  
  sudo python3 setup.py install
  
Verify the installation:  
  vol.py -h
  
**Analysis Techniques and Plugins**  
1. Image Information  
Plugin: imageinfo  
Retrieves basic information about the memory image, such as OS version, service pack level, architecture, and timestamps. This is essential for determining the appropriate profile for further analysis.  

2. Process Analysis  
Plugins: pslist, psscan, pstree, psxview  
pslist: Lists all active processes, providing details like process ID, parent process ID, session ID, and CPU usage.  
psscan: Lists processes, including terminated ones, offering a comprehensive view of all processes that have been active.  
pstree: Displays processes in a hierarchical tree format, showing parent-child relationships.  
psxview: Provides insights into hidden or malicious processes.  

3. Command Line Analysis  
Plugin: cmdline  
Extracts and displays command-line arguments associated with processes, helping to gather valuable information about process execution.  

4. Kernel Modules and Drivers Analysis  
Plugins: ldrmodules, modscan, driverscan  
ldrmodules: Lists loaded modules and their details for each process.  
modscan: Scans the memory dump for loaded kernel modules (drivers).  
driverscan: Focuses on extracting and displaying information about loaded drivers.  

5. Dynamic Link Libraries (DLL) Analysis  
Plugin: dlllist  
Lists loaded DLLs for each process, revealing dependencies, injected DLLs, and potential malware activities.  

**Key Findings**  

**Suspicious Processes**  
huuhroi.exe: Unrecognized process with high threads and handles count.  
vssadmin.exe: Legitimate utility but suspicious due to quick start and exit.  
mscorsvw.exe: Multiple instances with high threads and handles.  
SearchIndexer.exe: High resource consumption.  
pythonw.exe: Presence of Python processes may indicate suspicious activity.  
sppsvc.exe: Unexpected invocation of software protection service.  

**Hidden and Malicious Processes**  
inject-x86.exe / inject-x64.exe: Code injection processes.  
TeslaCrypt2.exe: Associated with ransomware.  
cmd.exe: Abused for executing malicious commands.  

**Suspicious Drivers**  
spsys.sys, rspndr.sys, secdrv.SYS, NDProxy.SYS, HTTP.sys, afd.sys, usbohci.sys, tcpip.sys, atapi.sys: Potentially malicious or manipulated drivers. 

**DLL Anomalies**  
Unusual load times and unexpected DLL names or locations may indicate injected or dynamically loaded malicious DLLs.  

**Conclusion**  
This project demonstrates the use of Linux and the Volatility Framework for conducting comprehensive memory forensics on Windows systems. The analysis reveals several suspicious and potentially malicious activities, highlighting the importance of memory forensics in identifying security incidents.  

**Usage**  
Clone the repository:  
  git clone https://github.com/anashashme/windows-memory-forensics-using-linux.git  
  
Navigate to the project directory:  
  cd windows-memory-forensics-using-linux  
  
Follow the instructions in the provided scripts and documentation to set up the analysis environment and run the forensic plugins.  
License  
This project is licensed under the Apache License 2.0. See the LICENSE file for details.  
