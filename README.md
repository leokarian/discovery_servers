```
foo@bar:~$ discovery_servers.py -h
usage: discovery_servers.py [-h] (-s SERVER | -sf SERVERS_FILE)
                            (-u USER | -uf USERS_FILE)
                            (-p PASSWORD | -pf PASSWORDS_FILE) [--ssh SSH]
                            [--wmi WMI] [--rdp RDP] [--version]
```

Description: 
============
    Scan server/s to visualize open WMI, RDP or SSH ports, and try to login 
    with credentials given.

    Default ports to scan are:
       - SSH: 22
       - WMI: 135
       - RDP: 3389

```
options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

Server/s:
  You can choice scan only one server or a file containing a list of servers.

  -s SERVER, --server SERVER
                        Scan only the server passed
  -sf SERVERS_FILE, --servers-file SERVERS_FILE
                        Servers list file to scan

User/s:
  You can use a username or a file containing a list of usernames.

  -u USER, --user USER  User to use in credentials
  -uf USERS_FILE, --users-file USERS_FILE
                        User list file to use in credentials

Password/s:
  You can use a password or a file containing a list of passwords.

  -p PASSWORD, --password PASSWORD
                        Password to use in credentials
  -pf PASSWORDS_FILE, --passwords-file PASSWORDS_FILE
                        Password list file to use in credentials

Port/s:
  You can choice change the default ports.

  --ssh SSH             Port to use for SSH Scan. (Default: 22)
  --wmi WMI             Port to use for WMI Scan. (Default: 135)
  --rdp RDP             Port to use for RDP Scan. (Default: 3389)

Examples:
=========
   discovery_servers.py -s 192.168.1.110 -u Administrator -p password
   discovery_servers.py -sf servers.txt -uf users.txt -pf passwords.txt
   discovery_servers.py -sf servers.txt -u root -pf passwords.txt -ssh 2022

Use it responsibly.
```