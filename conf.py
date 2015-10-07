# Ip address of the bind/reverse shell. Add remote host address for bind shell and local host for reverse shell.

ip="192.168.169.136"

# Main site of the application

site="http://192.168.169.136"

# The url of the vulnerable application
# If the SQL Injection is discovered on GET request, make sure the injection variable is located as the last variable
# For example, the vulnerable url is => http://www.mysqloit.com/id.php?id=22&name=mysqloit and the vulnerable variable
# is 'id'. Convert the url to => "http://www.mysqloit.com/id.php?name=mysqloit&id=22" 

url="http://192.168.169.136/defcon/output.php?question=44444"

# Metasploit Framework directory

metasploit="/usr/local/metasploit"

# Datatype of the vulnerable variable. Should be either integer/string

datatype="string"

# Request type

request = "GET" #GET/POST

# This section is used for POST request only. Insert the vulnerable variable as 'post_injection'
# Other variables can be added as 'post_last_injection'
# For example, the parameter query is => foo=bar&abc=123&name=mysqloit and the vulnerable variable is 'name' 
#  
#  post_injection="name=mysqloit"
#  post_last_injection="&foo=bar&abc=123"
#  
#  Leave the post_last_injection to blank if only one variable is required

post_injection="question=4444"      
post_last_injection=""

# Agent

agent = "Mysqloit" #Why don't try to be more sneeky ?

debug = True

