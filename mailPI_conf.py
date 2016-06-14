#! /usr/bin/python
# mailPI configuration file

# Depending on your network configuration,
# you can use public DNS (Google's, OpenDNS, EasyDNS)
# or you need to use the local DNS (usually the local gateway)
# A.B.C.D format in a string, eg: '192.168.1.1'
DNSIP = ''

# int value
# 53 is the default DNS port
DNSPORT = 53

# the address use to communicate with the mx
# can be nonexistent
FAKADDR = 'itsme@mar.io'

# timeout value for the socket module
SKTTIMEOUT = 20
