# MySqloit

Forked from: https://code.google.com/p/mysqloit/

MySqloit is a SQL Injection takeover tool focused on LAMP (Linux, Apache,MySql,PHP) and  WAMP (Linux, Apache,MySql,PHP) platforms. It has an ability to upload and execute Metasploit shellcodes through the MySql SQL Injection vulnerability.


## Platform supported

1. Linux 

## Key Features

1. SQL Injection detection using time based injection method
2. Database fingerprint
3. Web server directory fingerprint
4. Payload creation and execution 

## Requirements

1. FILE privilege
2. Web server and database server must be in the same machine
3. Prior knowledge of the web server directory
4. For the LAMP platform, if the mysqld runs as a non root user, a writable web server directory is required

## Usage

./mysqloit.py -h

Example:

Attacking LAMP

On the recent versions of MySQL, mysqld refuses to run as a root unless the user forces them.
In this case, a writable web server directory is required

Condition A:
* mysqld runs as a root user
* web server directoy = /var/www

```
./mysqloit.py -p bind 4444 
./mysqloit.py -e /var/www /
```

Condition B:
* mysqld runs as a non root user
* web server root directory = /var/www
* writable web server directory = /var/www/upload

./mysqloit.py -p bind 4444 
./mysqloit.py -e /var/www /upload

Condition C:
* mysqld runs as a non root user
* web server root directory = /var/www
* writable web server directory = no writable directory

Exploit will fail


## Attacking WAMP

Condition A:

MySQL Windows always run as a LocalSystem.
In this case, a writable web server directory is not required.


Condition A:
* web server directory = C:\Program Files\Apache2\htdocs\

```
./mysqloit -p bind 4444
./mysqloit -e bind 4444 'C:\Program Files\Apache2\htdocs\' \
```

email: muhaimindz@gmail.com

### License

GPL v2 
