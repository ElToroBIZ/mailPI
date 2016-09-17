#! /usr/bin/python
# mailPI

## IMPORTS

import random
import socket
import telnetlib

import mailPI_conf as  conf

## CONFIGURATION

# IP and port of the DNS server used to find the mx
DNSIP = conf.DNSIP
DNSPORT = conf.DNSPORT

# address used to communicate with the mx server
FAKADDR = conf.FAKADDR

## TARGETS

# addresses that need to be tested
# list of strings
MAILADDRS = ['lorem@ipsum.com',
             'contact@example.net',
             'rick@roll.org']

## DATA

# Straight from the RFC
dns_error = {
        1:('FormErr', 'Format Error'),
        2:('ServFail', 'Server Failure'),
        3:('NXDomain', 'Non-Existent Domain'),
        4:('NotImp', 'Not Implemented'),
        5:('Refused', 'Query Refused'),
        6:('YXDomain', 'Name Exists when it should not'),
        7:('YXRRSet', 'RR Set Exists when it should not'),
        8:('NXRRSet', 'RR Set that should exist does not'),
        9:('NotAuth', 'Server Not Authoritative for zone'),
        10:('NotAuth', 'Not Authorized'),
        11:('NotZone', 'Name not contained in zone')
    }

## FUNCTIONS

# string in, string out
# no name pointer technology implemented
def dns_naming(domainame):
    result = ''
    for name in domainame.split('.'):
        result += hex(len(name))[2:].zfill(2)
        result += ''.join([hex(ord(x))[2:].zfill(2) for x in name])
    return result+'00'

# string in, (string, string) out
# return the transaction ID, the dns query data
def gen_dnsquestion(domainame):
    # transaction ID
    transid = bin(random.getrandbits(16))[2:].zfill(16) # 16 bits

    # flags and codes
    QRflag = '0' # 1 bit, query 0, response 1
    Opcode = '0000' # 4 bits
    AAflag = '0' # 1 bit, authoritative answer
    TCflag = '0' # 1 bit, truncation (switch or not from UDP to TCP)
    RDflag = '1' #recursion desired
    RAflag = '0' #recursion available
    zerosflag = '000' # 3 zeros
    RCode = '0000' #response code
    flags = QRflag+Opcode+AAflag+TCflag+RDflag+RAflag+zerosflag+RCode

    # counts
    QDcount = '1'.zfill(16) # number of question
    ANcount = '0'.zfill(16) # number of rr in answer
    NScount = '0'.zfill(16) # number of rr in authority
    ARcount = '0'.zfill(16) # number of rr in additional
    counts = QDcount+ANcount+NScount+ARcount

    # dns header
    header = transid+flags+counts # in binary
    header = ''.join([chr(int(header[x*8:(x+1)*8], 2))
                      for x in range(len(header)/8)])

    # dns question
    dnsquestion = dns_naming(domainame)
    dnsquestion += hex(15)[2:].zfill(4)
    dnsquestion += hex(1)[2:].zfill(4) # 1 for IN (Internet), sorry chaosnet
    dnsquestion = ''.join([chr(int(dnsquestion[x*2:(x+1)*2], 16))
                           for x in range(len(dnsquestion)/2)])

    return transid, header+dnsquestion

# (string, string) in, (boolean,int) out
# return the legitimacy of the answer header, the number of answer
def check_answerhdr(answerhdr, transid):
    legit = True
    
    # check transid match
    if answerhdr[:len(transid)] != transid:
        legit = False
        
    answerhdr = ''.join([bin(ord(x))[2:].zfill(8)
                         for x in answerhdr[len(transid):]])

    # check QRflag
    if answerhdr[0] != '1':
        legit = False
        print '\terror: dns answer is not an answer (QRflag)'

    # check response code
    if answerhdr[12:16] != '0000':
        legit = False
        errcode = int(answerhdr[12:16], 2)
        if errcode in dns_error:
            print '\terror: response code: '+str(errcode)+'. '+dns_error[errcode][0]+': '+dns_error[errcode][1]
        else:
            print '\terror: response code: '+str(errcode)

    # check number of rr in answer
    ANcount = int(answerhdr[32:48], 2)
    NScount = int(answerhdr[48:54], 2)
    ARcount = int(answerhdr[54:70], 2)
    if ANcount+NScount+ARcount<1:
        legit = False
        print '\terror: number of answer elements: '+str(ANcount+NScount+ARcount)
    
    return legit,ANcount

# (string, string) in, (boolean) out
# return the legitimacy of the answer query part
def check_query(answer,maildomain):
    # wouldn't it be easier to compare the original query and the query in answer ?
    legit = True

    empiricdomain = answer.split(chr(0))[0]
    empiricdomain = ''.join([hex(ord(x))[2:].zfill(2)
                             for x in empiricdomain])+'00'

    theoricdomain = dns_naming(maildomain)

    # check if matching domain
    if theoricdomain != empiricdomain:
        legit = False
        print '\terror: the domain in the answer is not the domain in the query'

    answer = answer[len(empiricdomain)/2:]

    # check if MX record
    if answer[:2] != chr(0)+chr(15):
        legit = False
        print '\terror: the record type in the answer is not the record type in the query'
        
    return legit

# (string, int) in, (list of strings) out
# extract the mx domain names from the answer
def extract_answers(answer,answercount):
    answernumber = 0
    fullanswer = answer # keep a full copy for name ptr sake
    answer = answer.split(chr(0)+chr(15),1)[1][2:] # drop the original answer part for easier calculations
    
    answers = []

    k = 0    
    while k<len(answer):
        
        # name
        if bin(ord(answer[k]))[2:].zfill(8)[:2] == '11':
            k += 2 # skip the name pointer, although maybe we should care
        else:
            # Warning : bugged at some point, undetermined reasons
            k = answer.index(chr(0), 1)
            k += 1+int(answer[k]) # skip the name, although maybe we should care
        
        # type
        if answer[k:k+2] != chr(0)+chr(15):
            # something is wrong, it pops up when it seems it should not
            # but still also pop up when needed ...
            print '\terror: answer is not an mx ?'
            break
        else:
            k += 2 # skip the type, we're open-minded,

        k += 2 # skip the class, cause punk is a fashion
        k += 4 # skip the TTL, we're cachin' nothin'
        
        datalen = int(''.join([str(ord(x)) for x in answer[k:k+2]]))
        k += 2 # skip the datalen, we got what we came for
        k += 2 # skip the preference, all the gentlemen are dead
        mxdnsname = answer[k:k+datalen-2]
        
        l = 0
        mxname = []
        while l<len(mxdnsname):
            d = mxdnsname[l]
            if bin(ord(d))[2:].zfill(8)[:2] == '11':
                # c00c is the header offset
                p1 = bin(ord(mxdnsname[l])-int('c0',16))[2:].zfill(6)
                p2 = bin(ord(mxdnsname[l+1])-int('0c',16))[2:].zfill(8)
                
                mxdnsname = mxdnsname[:l]+fullanswer[int(p1+p2,2):].split(chr(0),1)[0]+chr(0)+mxdnsname[l+2:]
                # the chr(0) may be the end of the name
                # if there is only one ptr
                # if there is 2or+ ptrs,
                # it will be the chr(0) of the MX type of the next answer
                # that will be taken
                # but, because there is always one chr(0)
                # at the end of a domain name we can just cut the garbage later
                
                # mxdnsname will temporary have garbage elements
                # coming from previous answers in the meantime
                
                # this is a way to make this weird recursion works
            else:
                elementlen = ord(mxdnsname[l])
                l += 1
                mxname.append(mxdnsname[l:l+elementlen])
                l += elementlen
                
        if '' in mxname:
            mxname = mxname[:mxname.index('')]
            # cut the garbage in case of chained pointers
            
        answers.append('.'.join(mxname))
        k += datalen-2 # move k to after the answer
        answernumber += 1
        
        # do we have all the answer ?
        if answernumber >= answercount:
            k=len(answer) # let's end this loop
        
    return answers

## MAIN

socket.setdefaulttimeout(conf.SKTTIMEOUT) # configure a timeout for the socket module
domainmx = {} # cache the queried domain in case of multiple addresses in the same domain

for mailaddr in MAILADDRS:

    print mailaddr
    
    maildomain = mailaddr.split('@')[1] # account@domainname -> domainname

    if maildomain not in domainmx:
        answers = []
        transid, msg = gen_dnsquestion(maildomain)
        transid = ''.join([chr(int(transid[x*8:(x+1)*8],2)) for x in range(len(transid)/8)])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #connecting in IP/UDP
        try:
            sock.sendto(msg, (DNSIP, DNSPORT)) # to the DNS, asking for the mx of the domain
            data, server = sock.recvfrom(2048)
        except Exception as e:
            # connectivity issue, DNSIP issue, DNSPORT issue, probably
            print '\terror: socket to '+DNSIP+' on port '+str(DNSPORT)+' in UDP'
            print '\terror: '+str(e)
            break
        finally:
            sock.close()

        dnsheader = data[:12]
        okayheader,answercount = check_answerhdr(dnsheader, transid)
        if okayheader:
            dnsanswer = data[12:]
            okayquery = check_query(dnsanswer, maildomain)
            if okayquery:
                answers = extract_answers(dnsanswer,answercount)
                if len(answers)>0:
                    domainmx[maildomain] = answers
                else:
                    domainmx[maildomain] = ['NOPE','Empty answer array (DNS is not forwarding probably)']
            else:
                domainmx[maildomain] = ['NOPE','Compromised answer (not okayquery)']
        else:
            domainmx[maildomain] = ['NOPE','No valid MX answer (not okayheader)']
            
    if domainmx[maildomain][0] != 'NOPE':
        mx = random.choice(domainmx[maildomain])
        port = '25'

        tn = telnetlib.Telnet()
        # let's have a chat with the mx
        tn.open(mx,port)
        tn.read_until('\n')
        tn.write('HELO '+FAKADDR.split('@')[1]+'\r\n')
        tn.read_until('\n')
        tn.write('MAIL FROM:<'+FAKADDR+'>\r\n')
        tn.read_until('\n')
        tn.write('RCPT TO:<'+mailaddr+'>\r\n')

        mxanswer = tn.read_until('\n')
        tn.close()

        if mxanswer[:3] == '250':
            print '\t'+mailaddr+': EXISTS (according to '+mx+')'
        elif mxanswer[:3] == '550':
            print '\t'+mailaddr+': NOT EXIST (according to '+mx+')'
        else:
            print '\t'+mailaddr+' with '+mx
            print '\terror: '+mxanswer
    else:
        print '\twarning: '+domainmx[maildomain][1]
    print ""
