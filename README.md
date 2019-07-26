# What is VulnBuster?
VulnBuster is command-line tool we developed that is able to detect LOLBins and generate relevant CVE reports based on the installed applications and drivers found on the system. A key defining feature is that the tool does not require administrator privileges and does not require any external program or dependency to run.




# What is a LOLBin?
Before we go into detail on the tools’ main features, we would like to elaborate on what Living off the Land Binaries are. 
Living off the Land Binaries, or LOLBins for short, are trusted tools that are either provided by the operating system or pre-installed by the organization. These  do have a legitimate purpose,LOLBins are dangerous as they are hard to detect using conventional antivirus/detection tools. Our tool is able to detect these LOLBins.

# Technology Used
The tool was developed in C#, and is built as a dll file. We use ReGasm, a built-in Windows utility to run the tool. ReGasm is used to register/unregister assemblies. ReGasm has an exploit in which we can specify in our source code the code to be ran during the registration/unregistration process. Since non-administrators can only unregister assemblies, we put the main body of our code to be ran during the unregistration process. We do this through the ComUnregisterFunction attribute in C#. Therefore ironically, we exploit a LOLBin to be able to run our code without admin rights.

# Main Features
The first feature of the tool is that it is able to generate CVE reports for the software installed on the computer. They can either auto-generate the CVE reports for all applications or select the applications to generate the CVE reports for manually.

The database used to generate these CVE reports comes in the form of json files from the NVD website data feed: (https://nvd.nist.gov/vuln/data-feeds)
We serialize the JSON files into a single C# root object, and use that object to reference all CVE items for that file.
The CVE Report comes in the form of a text file, which contains the following properties:
1. CVE ID
2. Description
3. Attack Vector
4. Attack Complexity
5. Privileges Required
6. User Interaction
7. Confidentiality Impact
8. Integrity Impact
9. Availability Impact
10. Base Score
11. Base Severity

# Video Demo
https://youtu.be/tVCXVLHksIw

# How to use our tool

1. Copy paste 'tool' folder in your Documents folder.
2. Run 'runtool.bat'. This will execute the command "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /U VulnBuster.dll".



