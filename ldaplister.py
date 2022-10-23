#!/usr/bin/env python3

import ldapl.ldapquery as ldapl
import argparse


def main():
    parser = argparse.ArgumentParser(description="LDAP Tools")
    parser.add_argument('-t' '--target-ip', required=False, type=str,
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
    parser.add_argument("--basedn", required=False, type=str,
                        default=None, dest="basedn",
                        help='Specify the base distinguished name. Get this using "-a" for an anonymous bind.')
    parser.add_argument("--password-search", required=False,
                        default=False, action='store_true', dest='pass_search',
                        help="Search all accounts for a password in the description.")
    parser.add_argument("--get-all-users", required=False,
                        default=False, action='store_true', dest='get_users',
                        help="Dump all AD users.")

    args = parser.parse_args()

    if args.anony is True:
        ldap_query = ldapl.LdapQuery(args.target, "", "", "")
        domain_details = ldap_query.get_domain_information()
        print(*domain_details, sep='\n')
        exit(0)

    if args.pass_search is True:
        ldap_query = ldapl.LdapQuery(args.target, args.username, args.password, args.basedn)
        ldap_query.authenticated_logon()
        ldap_query.query_for_passwords()
        exit(0)

    if args.get_users is True:
        ldap_query = ldapl.LdapQuery(args.target, args.username, args.password, args.basedn)
        ldap_query.authenticated_logon()
        ldap_query.query_all_users()
        exit(0)


if __name__ == "__main__":
    main()
