#!/usr/bin/python
# *********************************************************************

__author__ = "Leonardo Karabogosian (leonardo.karabogosian@gmail.com)"
__version__ = "0.1"
__last_modification__ = "2023.03.05"

# *********************************************************************
import argparse
import os
import subprocess
import sys
import textwrap
import warnings
import signal

import nmap
import wmi
from print_colours import *

from cryptography.utils import CryptographyDeprecationWarning
with warnings.catch_warnings():
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    import paramiko


def ssh_authentication(hostname, port, list_users, list_passwords):
    try:
        # Crear una conexión SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        creds = {}
        for username in list_users:
            for password in list_passwords:
                try:
                    sys.stdout.write("\tSSH login with credentials \"%s - %s\" ... " % (username, password))
                    sys.stdout.flush()
                    ssh.connect(hostname, username=username, password=password, port=port, look_for_keys=False, allow_agent=False)
                    # Verificar la conexión
                    stdin, stdout, stderr = ssh.exec_command('hostname')
                    hostname_info = stdout.read().decode('utf-8').strip()
                    stdin, stdout, stderr = ssh.exec_command('uname -a')
                    osbase_info = stdout.read().decode('utf-8').strip()
                    if stderr.channel.recv_exit_status() != 0:
                        wr_red("Wrong credentials for %s \n" % username)
                        continue
                except Exception as e:
                    wr_red("Error connecting. MSG: %s \n" % e)
                    continue
                # Cerrar conexión SSH
                wr_green("SSH CONNECTED!\n")
                print("\tHostname: %s - OS Base: %s" % (hostname_info, osbase_info))
                ssh.close()
                return True
        return False
    except paramiko.AuthenticationException:
        wr_red("Wrong credentials for SSH!\n")
        return False
    except Exception as e:
        print(e)
        return False


def wmi_authentication(hostname, list_users, list_passwords):
    # Documentation:
    # http://timgolden.me.uk/python/wmi/tutorial.html
    # http://timgolden.me.uk/python/wmi/cookbook.html
    creds = {}
    for username in list_users:
        for password in list_passwords:
            sys.stdout.write("\tWMI login with credentials \"%s - %s\" ... " % (username, password))
            sys.stdout.flush()
            try:
                c = wmi.WMI(hostname, user=username, password=password)
                wr_green("CONNECTED!\n")
                for os_info in c.Win32_OperatingSystem():
                    print("\tOS Name: %s - OS SystemBase: %s" % (os_info.CSName, os_info.Caption))
                return True
            except wmi.x_access_denied as ad:
                wr_red('Access Denied!\n')
            except Exception as e:
                sys.stdout.write('\n')
                print(e)
                break
    return False


def get_users_passwords(pre_filter, menu_args):
    users = list()
    passwords = list()
    if menu_args.users_file:
        with open(args.users_file.name, 'r') as users_list:
            for user in users_list:
                user = user.strip()
                if user.startswith(pre_filter):
                    users.append(user.replace(pre_filter, ''))
                elif not user.startswith('['):
                    users.append(user)
    elif menu_args.user:
        users.append(menu_args.user)

    if menu_args.passwords_file:
        with open(args.passwords_file.name, 'r') as password_list:
            for password in password_list:
                password = password.strip()
                if password.startswith(pre_filter):
                    passwords.append(password.replace(pre_filter, ''))
                elif not password.startswith('['):
                    passwords.append(password)
    elif menu_args.password:
        passwords.append(menu_args.password)
    return users, passwords


def scan_server(hostname, menu_args):
    try:
        ssh_port = str(menu_args.ssh)
        rdp_port = str(menu_args.rdp)
        wmi_port = str(menu_args.wmi)

        # Create an object nmap.PortScanner
        nm = nmap.PortScanner()
        wr_yellow("Ping scanning \"%s\"... " % hostname)
        res = nm.scan(hostname, arguments='-sn')
        ip_host = nm.listscan(hostname)[0]
        if res['scan'] and res['scan'][str(ip_host)]['status']['state'] == 'up':
            wr_green('UP!\n')
        else:
            wr_red('DOWN! ... Quitting scan...\n')
            return False

        # Scan RDP and WMI
        wr_yellow("  Scanning WMI port... ")
        res = nm.scan(hostname, wmi_port)
        ip_host = nm.listscan(hostname)[0]
        wmi_status = res['scan'][str(ip_host)]['tcp'][int(wmi_port)]['state']
        if wmi_status == 'open':
            wr_green("WMI Open!\n")
            wmi_status = wmi_status.upper()
            list_users, list_passwords = get_users_passwords('[windows]', menu_args)
            wmi_auth_res = wmi_authentication(hostname, list_users, list_passwords)
            wr_yellow("  Scanning RDP on %s... " % hostname)
            res = nm.scan(hostname, rdp_port)
            ip_host = nm.listscan(hostname)[0]
            rdp_status = res['scan'][str(ip_host)]['tcp'][int(rdp_port)]['state']
            if rdp_status == 'open':
                wr_green("RDP Open!\n")
                rdp_status = rdp_status.upper()
            else:
                wr_red("RDP Closed!\n")
        else:
            wr_red("WMI Closed!\n")
            wr_yellow("  Scanning SSH on %s... " % hostname)
            res = nm.scan(hostname, ssh_port)
            ip_host = nm.listscan(hostname)[0]
            ssh_status = res['scan'][str(ip_host)]['tcp'][int(ssh_port)]['state']
            if ssh_status == 'open':
                wr_green("SSH Open! \n")
                ssh_status = ssh_status.upper()
                list_users, list_passwords = get_users_passwords('[linux]', menu_args)
                ssh_auth_res = ssh_authentication(hostname, ssh_port, list_users, list_passwords)
                return True
            else:
                wr_red("RDP and SSH ports closed.\n")
                return False
    except Exception as e:
        wr_red_white("GRAVE: Error al escanear el servidor\n")
        wr_red_white("Exception program: \n%s \n" % e)


def signal_handler(sig, frame):
    print("\n")
    wr_red_white('\nYou pressed Ctrl+C! Exitting...')
    print("\n")
    sys.exit(0)


def create_help_menu():
    # ArgParse: https://docs.python.org/es/3/library/argparse.html
    my_parser = argparse.ArgumentParser(prog=str(os.path.basename(__file__)),
                                        formatter_class=argparse.RawDescriptionHelpFormatter,
                                        description=textwrap.dedent('''\
                                            Description: 
                                            ============
                                                Scan server/s to visualize open WMI, RDP or SSH ports, and try to login 
                                                with credentials given.
                                                
                                                Default ports to scan are:
                                                   - SSH: 22
                                                   - WMI: 135
                                                   - RDP: 3389
                                            '''),
                                        epilog=textwrap.dedent('''\
                                            Examples:
                                            =========
                                               %(prog)s -s 192.168.1.110 -u Administrator -p password
                                               %(prog)s -sf servers.txt -uf users.txt -pf passwords.txt
                                               %(prog)s -sf servers.txt -u root -pf passwords.txt -ssh 2022
                                               
                                            Use it responsibly.'''))

    servers_group = my_parser.add_argument_group('Server/s', 'You can choice scan only one server or a file containing'
                                                             ' a list of servers.')
    servers = servers_group.add_mutually_exclusive_group(required=True)
    servers.add_argument('-s', '--server', type=str, help='Scan only the server passed')
    servers.add_argument('-sf', '--servers-file', type=open, help='Servers list file to scan')

    users_group = my_parser.add_argument_group('User/s', 'You can use a username or a file containing a list of '
                                                         'usernames.')
    users = users_group.add_mutually_exclusive_group(required=True)
    users.add_argument('-u', '--user', type=str, help='User to use in credentials')
    users.add_argument('-uf', '--users-file', type=open, help='User list file to use in credentials')

    passwords_group = my_parser.add_argument_group('Password/s', 'You can use a password or a file containing a list '
                                                                 'of passwords.')
    passwords = passwords_group.add_mutually_exclusive_group(required=True)
    passwords.add_argument('-p', '--password', type=str, help='Password to use in credentials')
    passwords.add_argument('-pf', '--passwords-file', type=open, help='Password list file to use in credentials')

    ports_group = my_parser.add_argument_group('Port/s', 'You can choice change the default ports.')
    ports_group.add_argument('--ssh', type=int, default=22, help='Port to use for SSH Scan.')
    ports_group.add_argument('--wmi', type=int, default=135, help='Port to use for WMI Scan.')
    ports_group.add_argument('--rdp', type=int, default=3389, help='Port to use for RDP Scan.')

    my_parser.add_argument('--version', action='version', version='Program version: %(prog)s version 0.1')
    return my_parser


if __name__ == "__main__":
    parser = create_help_menu()
    try:
        args = parser.parse_args()
        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit()
    except FileNotFoundError as fnf:
        print(fnf)
        sys.exit(-1)

    # Signal to caught Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    wr_purple('Running. Press Ctrl+C to abort...\n')
    wr_line()

    if args.server:
        scan_server(args.server.strip(), args)
        wr_line()
    elif args.servers_file:
        with open(args.servers_file.name, 'r') as server_list:
            for host in server_list:
                if host.strip():
                    scan_server(host.strip(), args)
                    wr_line()
    else:
        print("A problem ocurred: No servers for scan.")
