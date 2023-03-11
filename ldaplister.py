#!/usr/bin/env python3

import Core.ldapquery
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="LDAP Tools")
    parser.add_argument('-t', '--target-ip', required=True, type=str,
                        default=None, dest="target",
                        help="Specify the target IP address.")
    parser.add_argument('-a', '--anonymous', required=False,
                        default=False, action='store_true', dest='anony',
                        help="Specifies that an anonymous bind will be performed and Domain details returned.")
    parser.add_argument('-u', '--username', required=False, type=str,
                        default=None, dest="username",
                        help='Specify account username.')
    parser.add_argument("-p", '--password', required=False, type=str,
                        default=None, dest="password",
                        help='Specify account password.')
    parser.add_argument("--base-dn", required=False, type=str,
                        default=None, dest="basedn",
                        help='Specify the base distinguished name. Get this using "-a" for an anonymous bind.')
    parser.add_argument("--password-search", required=False,
                        default=False, action='store_true', dest='pass_search',
                        help="Search all accounts for a password in the description.")
    parser.add_argument("--get-all-users", required=False,
                        default=False, action='store_true', dest='get_users',
                        help="Dump all AD users.")
    parser.add_argument("--get-all-computers", required=False,
                        default=False, action='store_true', dest='get_computers',
                        help="Dump all AD computers.")
    parser.add_argument("--get-disabled-accounts", required=False,
                        default=False, action='store_true', dest="disabled_accounts",
                        help="Dump all disabled accounts.")
    parser.add_argument("--unconstrained-delegation", required=False,
                        default=False, action='store_true', dest="unconstrained_delegation",
                        help="Accounts with Unconstrained Delegation")

    args = parser.parse_args()

    ldap_query = Core.ldapquery.LdapQuery(args.target, args.username, args.password, args.basedn)
    ldap_query.authenticated_logon()
    # ldap_query.query_reversible_password()

    if args.anony is True:
        ldap_query = Core.ldapquery.LdapQuery(args.target, "", "", "")
        domain_details = ldap_query.get_domain_information()
        print(domain_details[0], domain_details[1], domain_details[2], domain_details[3], domain_details[4], sep='\r\n')
        exit(0)

    if args.pass_search is True:
        ldap_query.query_for_passwords()
        exit(0)

    if args.get_users is True:
        ldap_query.query_all_users()
        exit(0)

    if args.get_computers is True:
        ldap_query.query_all_computers()
        exit(0)

    if args.disabled_accounts is True:
        ldap_query.query_disabled_accounts()
        exit(0)

    if args.unconstrained_delegation is True:
        ldap_query.query_unconstrained_delegation()
        exit(0)

if __name__ == "__main__":
    main()
