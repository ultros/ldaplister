import ldap3
import sys
import json


class LdapQuery:

    def __init__(self, target: str, username: str, password: str, basedn: str):
        self.target = target
        self.username = username
        self.password = password
        self.basedn = basedn
        self.connection = ""
        self.server = ""

    def get_domain_information(self) -> tuple:
        """Gather server information using an anonymous logon against a target.
        Returns the defaultNamingContext and the dnsHostName for the target.
        """
        self.server = ldap3.Server(self.target, get_info=ldap3.ALL)
        self.connection = ldap3.Connection(self.server, user="", password="")
        self.connection.bind()
        json_server_data = self.server.info.to_json()
        data_dict = json.loads(json_server_data)

        return f"DNS Hostname: {data_dict['raw']['dnsHostName'][0]}", \
            f"Base DN: {data_dict['raw']['defaultNamingContext'][0]}", \
            f"Domain Controller Functionality Level: {data_dict['raw']['domainControllerFunctionality'][0]}", \
            f"Controller Functionality Level: {data_dict['raw']['domainFunctionality'][0]}", \
            f"Forest Functionality Level: {data_dict['raw']['forestFunctionality'][0]}"

    def authenticated_logon(self) -> None:
        server = ldap3.Server(self.target, get_info=ldap3.ALL)
        self.connection = ldap3.Connection(server, user=self.username, password=self.password)
        self.connection.bind()


    def query_schema(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(cn=schema)",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=ldap3.ALL_ATTRIBUTES,
                                                     generator=False)
        for entry in self.connection.entries:
            print(entry)

    def query_all_users(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(objectCategory=user)",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=ldap3.ALL_ATTRIBUTES,
                                                     generator=False)

        for entry in self.connection.entries:
            print(entry)

    def query_for_passwords(self) -> None:
        """Checks the "description" field for User accounts with "password" in the description.
        """
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                                  search_filter="(&(objectClass=user)"
                                                                                "(description=*pass*))",
                                                                  search_scope=ldap3.SUBTREE,
                                                                  attributes=['cn', 'description'],
                                                                  generator=False)

        for entry in self.connection.entries:
            print(entry)

    def query_all_computers(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                                  search_filter="(&(objectClass=computer))",
                                                                  search_scope=ldap3.SUBTREE,
                                                                  attributes=[ldap3.ALL_ATTRIBUTES],
                                                                  generator=False)

        for entry in self.connection.entries:
            print(entry)

    def query_disabled_accounts(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(&(objectCategory=person)(objectClass=user)"
                                                                   "(userAccountControl:1.2.840.113556.1.4.803:=2))",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=[ldap3.ALL_ATTRIBUTES],
                                                     generator=False)
        for entry in self.connection.entries:
            print(entry)

    def query_unconstrained_delegation(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(&(objectCategory=user)"
                                                                   "(userAccountControl:1.2.840.113556.1.4.803:="
                                                                   "524288))",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=[ldap3.ALL_ATTRIBUTES],
                                                     generator=False)
        for entry in self.connection.entries:
            print(entry)

    def query_smart_card(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(&(objectCategory=person)(objectClass=user)"
                                                                   "(userAccountControl:1.2.840.113556.1.4.803:="
                                                                   "262144))",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=[ldap3.ALL_ATTRIBUTES],
                                                     generator=False)
        for entry in self.connection.entries:
            print(entry)

    def query_reversible_password(self) -> None:
        self.connection.extend.standard.paged_search(search_base=self.basedn,
                                                     search_filter="(&(objectCategory=person)(objectClass=user)"
                                                                   "(userAccountControl:1.2.840.113556.1.4.803:=128))",
                                                     search_scope=ldap3.SUBTREE,
                                                     attributes=[ldap3.ALL_ATTRIBUTES],
                                                     generator=False)
        for entry in self.connection.entries:
            print(entry)