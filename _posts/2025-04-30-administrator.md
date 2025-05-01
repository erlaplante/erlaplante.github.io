---
title: Administrator
date: 2025-04-30 00:00:00 -0800
categories: [Patch the Box]
tags: [hack the box,windows,active directory,wazuh,sysmon]
description: Assumed compromise Windows machine, BloodHound is used to identify attack paths across various user Access Control Entries. Review ways to identify detection of BloodHound.py.
---

### Overview

This is a medium level Hack The Box machine running as a domain controller. It is an assumed compromise, meaning low privileged credentials are provided however, standard attack methodologies must still be used to get to the "user" and "root" flags. The focus is on Active Directory based reconnaissance and I highlight detection methods along the way.

### Attack Tactics

#### Reconnaissance
The password for the low privileged user Olivia is provided before spawning the machine, after saving this an nmap scan is ran to see typical ports open for a Windows domain controller as well as 21, a default port for FTP. I initially used `NetExec` to get a users list and test the received credentials with SMB and WINRM.

```bash
nxc smb $IP -u olivia -p ichliebedich --users
nxc winrm $IP -u users.txt -p ichliebedich --continue-on-success
```

It turned out that Olivia had WINRM access but the password was not reused for any of the other accounts. With WINRM access I used `evil-winrm` to check the file system. I started with some light enumeration of high privileged groups with `net`, looked for interesting privileges with `whoami` and did not see anything helpful. In the `C:\Users` directory Emily had a folder and `C:\inetpub` also seemed unusual. I ran winpeas as well but reviewing that output did not reveal any immediate attack paths either.

##### BloodHound
Running BloodHound luckily turned out to eventually provide all the information needed to compromise the machine. When initially working on this box I used `SharpHound.exe` locally since I was already logged in with evil-wirnm. This will be rather noisy though so for this writeup I would rather show using [BloodHound.py](https://github.com/dirkjanm/BloodHound.py), where the desired version for the BloodHound GUI should be used, either Legacy or Community Edition.

```bash
bloodhound-ce-python -u olivia -p ichliebedich -d administrator.htb -c all -ns $IP
```

By default, Wazuh detected the remote logons from BloodHound:

![image](https://i.postimg.cc/8knyMQrk/administrator-default.png){: width='1165' height='87'}

The article [Detecting SharpHound Active Directory activities with Wazuh](https://wazuh.com/blog/detecting-sharphound-active-directory-activities/) details the steps well as the title describes. I followed along by including the 5145 event IDs (by removing it from the Wazuh default exclusions that the article warns about). The "Group Policy Object configuration" steps they list are for enabling auditing of file share success events with the GUI. I used these `auditpol` commands instead which seemed to achieve the same goal, setting the auditing and then verifying the results respectively:

```powershell
auditpol /set /subcategory:'Detailed File Share' /success:enable
auditpol /get /category:"Object Access"
```

I also only implemented the last rule as it applies to the `BloodHound.py` remote connections rather than much of the local SharpHound activity that should be relatively easy to detect.

> __Detect:__ Wazuh rule to detect null session connections which occurs with BloodHound:
{: .prompt-tip}

```
<group name="nullsession-connection">
<!-- This rule detects attempts to enumerate DC through null session connections.-->
    <rule id="190003" frequency="2" timeframe="3" level="5">
        <if_sid>60103</if_sid>
        <field name="win.system.eventID" type="pcre2">^5145$</field>
        <field name="win.eventdata.relativeTargetName" type="pcre2">^srvsvc|lsarpc|samr$</field>
        <field name="win.eventdata.subjectUserName" type="pcre2">^(?!.*\$$).*$</field>
        <description> Possible Network Service enumeration by $(win.eventdata.subjectUserName) targeting $(win.eventdata.relativeTargetName).</description>
        <mitre>
            <id>T1087</id>
        </mitre>
    </rule>
</group>
```

Triggered detections after implementing the rule:
![image](https://i.postimg.cc/V6Zgcpyk/administrator-null-conn-rule.png){: width='761' height='202'}

#### Lateral Movement
With the BloodHound data gathered attack paths can be analyzed. I already went through the [prerequisites](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) with Docker for the Community Edition so ran this to get the web interface ready:

```bash
curl -L https://ghst.ly/BHCEDocker | docker compose -f - up
```
Selecting Olivia's account and going to `Outbound Object Control` > `First Degree Object Control` the GenericAll privilege can be abused by Olivia against Michael's account:

![image](https://i.postimg.cc/R0T19F6R/administrator-genericall.png){: width='747' height='310'}

The Linux abuse info explains the example command that can be ran (`dc` here was added along with FQDN and the domain in the `/etc/hosts` file):

```bash
net rpc password michael <NewPassword> -U administrator/olivia%ichliebedich -S dc
```
> __Detect:__ Existing Wazuh rules detecting remote logon and user account changes:
{: .prompt-tip}

![image](https://i.postimg.cc/Xqx77RKt/administrator-account-changed.png){: width='757' height='73'}

For the `User account changed` rule the message details shows the `Password Last Set` time:

![image](https://i.postimg.cc/pLmXR1m1/administrator-password-changed.png){: width='616' height='551'}

The logical step from here was to see Michael's access after setting the password. The same `Outbound Object Control` > `First Degree Object Control` check reveals that his account has the ForceChangePassword privilege over Benjamin:

![image](https://i.postimg.cc/442Ds4ps/administrator-force-change.png){: width='685' height='316'}

The same command from before can be used to change Benjamin's password:

```bash
net rpc password benjamin <NewPassword> -U administrator/michael%w1lliam5s -S dc
```

Then when looking at Benjamin's group memberships a non-standard group is easily identified. It's not clear from BloodHound what privileges the group offers but remembering that there was an FTP port open Benjamin has access there from this membership.

![image](https://i.postimg.cc/QCvY5tq7/administrator-share-group.png){: width='920' height='511'}

On the FTP server there was a `Backup.psafe3` file. Using `pwsafe2john` to get the hash for the Password Safe vault and `john` to crack it with `rockyou.txt` allows access to three more sets of credentials. Of interest is Emily's password as her account has GenericWrite access over Ethan's account under `First Degree Object Control` for Emily:

![image](https://i.postimg.cc/rwXYwDsX/administrator-genericwrite.png){: width='732' height='281'}

With this access one can perform a Targeted Kerberoast attack. With the GenericWrite access a ServicePrincipalName can be added to the targeted account and then standard Kerberoasting performed. In the example command I used `ntpdate` to update my VM's time to the Domain Controller and had to run these commands a couple times to avoid a clock skew error:

```bash
sudo ntpdate -u dc; python targetedKerberoast.py -d administrator.htb -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb --dc-ip dc -U ethan.txt
```

The same Wazuh detections fire after this:

![image](https://i.postimg.cc/Gmjw0FQS/administrator-targetedkerberoast.png){: width='1157' height='107'}

While the detection attributes accounts involved as before the detailed message data in this case does not indicate values that were changed which is an opportunity for a more granular detection:

![image](https://i.postimg.cc/mrrn00ht/administrator-targeted-ethan.png){: width='577' height='462'}

With Ethan's TGS hash this was easily cracked with `john`:

```bash
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt ethan.tgs
```

#### Privilege Escalation

BloodHound again rounds out the final step toward domain compromise by either checking `Outbound Object Control` for Ethan or `Principals with DCSync privileges` from the built-in Cypher queries.

![image](https://i.postimg.cc/9Mdy1fVT/administrator-dcsync.png){: width='1177' height='412'}

I ran `secretscat` (mentioned below) as it will run secretsdump followed by hashcat. When retesting certain aspects post compromise this allows the cracked and uncracked credentials to be easily formatted and referenced.

```bash
python secretscat.py -d administrator.htb -u ethan -p limpbizkit -dc $IP
```

> __Detect:__ The initially created Null Session Wazuh detection for the SAMR named pipe as well as remote logons were detected when running secretsdump:
{: .prompt-tip}

![image](https://i.postimg.cc/gkWmf2pj/administrator-secretsdump.png){: width='728' height='105'}

### secretscat
This is my implementation from the referenced Cyber Mentor video. I have not updated it but it still worked for this box and may come in handy for post exploitation of Active Directory environments.

- [secretscat](https://github.com/erlaplante/secretscat)

![image](https://i.postimg.cc/vB02XXG5/administrator-secretscat.png){: width='852' height='452'}

### Further Reading and Watching
- [Detecting SharpHound Active Directory activities with Wazuh](https://wazuh.com/blog/detecting-sharphound-active-directory-activities/)
- [Detecting Python BloodHound](https://medium.com/@cY83rR0H1t/detecting-python-bloodhound-8ae5130ebc60)
- [How Access Control Works in Active Directory Domain Services](https://learn.microsoft.com/en-us/windows/win32/ad/how-access-control-works-in-active-directory-domain-services)
- [Audit Detailed File Share](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-detailed-file-share)
- [Auditpol](https://ss64.com/nt/auditpol.html)
- [BloodHound.py](https://github.com/dirkjanm/BloodHound.py)
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [A Tour of BloodHound Community Edition](https://www.youtube.com/watch?v=YqTkSonRFKA&t=322s)
