#### Anonymous LDAP Enumeration
#### $ ./ldaplister.py -a -t 10.0.2.24
    DNS Hostname: dc.test.local
    Base DN: DC=test,DC=local
---
#### Password Search of Description
#### $ ./ldaplister.py -t 10.0.2.24 -u john -p P@ssw0rd --basedn "DC=test,DC=local" --password-search
    DN: CN=TestUser2,OU=users2,DC=test,DC=local - STATUS: Read - READ TIME: 2022-10-22T22:10:03.233627
        cn: TestUser2
        description: password: test

    DN: CN=msaMunSrv1,CN=Managed Service Accounts,DC=test,DC=local - STATUS: Read - READ TIME: 2022-10-22T22:18:13.401519
        cn: msaMunSrv1
        description: pass service account
---
#### Get All Users
$ ./ldaplister.py -t 10.0.2.24 -u john -p P@ssw0rd --basedn "DC=test,DC=local" --get-all-users

    distinguishedName: CN=Anne,CN=Users,DC=test,DC=local
    ...
    distinguishedName: CN=msaMunSrv1,CN=Managed Service Accounts,DC=test,DC=local
