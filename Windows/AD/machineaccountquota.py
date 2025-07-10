#!/usr/bin/env python3
import ldap3
 
target_dn = "DC=test,DC=co,DC=uk" # change this
domain = "test.co.uk" # change this
username = "*******" # change this
password = "******" # change this
 
user = "{}\\{}".format(domain, username)
server = ldap3.Server(domain)
connection = ldap3.Connection(server = server, user = user, password = password, authentication = ldap3.NTLM)
connection.bind()
connection.search(target_dn,"(objectClass=*)", attributes=['ms-DS-MachineAccountQuota'])
print(connection.entries[0])