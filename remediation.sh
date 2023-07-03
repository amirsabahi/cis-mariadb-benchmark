#!/bin/bash

# NOTE: Not a complete list of remediation.

read -p "Enter MariaDB Username: " username
read -s -p "Enter MariaDB Password: " password
echo
read -p "Enter MariaDB Host (default: 127.0.0.1): " host
host=${host:-127.0.0.1}
read -p "Enter MariaDB Port (default: 3306): " port
port=${port:-3306}

# Set permissions and ownership for /var/lib/mysql
chmod -R 750 /var/lib/mysql/
chown -R mysql:mysql /var/lib/mysql/

# Check if /var/log/mysql/mysql.log exists and set permissions and ownership
if [ -f /var/log/mysql/mysql.log ]; then
    chmod 660 /var/log/mysql/mysql.log
    chown mysql:mysql /var/log/mysql/mysql.log
fi

# Check if /var/lib/mysql/server_audit.log exists and set permissions and ownership
if [ -f /var/lib/mysql/server_audit.log ]; then
    chmod 660 /var/lib/mysql/server_audit.log
    chown mysql:mysql /var/lib/mysql/server_audit.log
fi

# Check if /usr/lib/mysql/plugin/ exists and set permissions and ownership
if [ -d /usr/lib/mysql/plugin/ ]; then
    chmod -R 550 /usr/lib/mysql/plugin/
    chown -R mysql:mysql /usr/lib/mysql/plugin/
fi

if [ -f /etc/mysql/encryption/keyfile.enc ]; then
    chmod 750 /etc/mysql/encryption/keyfile.enc
    chown mysql:mysql /etc/mysql/encryption/keyfile.enc
fi

if [ -f /etc/mysql/encryption/keyfile.key ]; then
    chmod 750 /etc/mysql/encryption/keyfile.key
    chown mysql:mysql /etc/mysql/encryption/keyfile.key
fi

# Disable MariaDB Command History
ln -s /dev/null $HOME/.mysql_history

# Harden Usage for 'local_infile' on MariaDB Clients
mariadb --local-infile=0 --load-data-local-dir=/var/lib/mysql

# Install mariadb-plugin-cracklib-password-check
apt update
apt-get --assume-yes install mariadb-plugin-cracklib-password-check

# MariaDB Commands
# Run the SQL commands
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "SET GLOBAL slow_query_log = 'OFF';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "SET GLOBAL general_log = 'OFF';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "SET GLOBAL sql_mode = 'STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "INSTALL SONAME 'simple_password_check';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "INSTALL SONAME 'cracklib_password_check';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "INSTALL SONAME 'server_audit';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "SET GLOBAL sql_mode ='STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';"
mariadb -u"$username" -p"$password" -h"$host" -P"$port" -e "alter user 'root'@'localhost' identified via 'unix_socket'; set password for 'mysql'@'localhost' = 'invalid'; set password for 'mariadb.sys'@'localhost' = 'invalid';"
echo -e "\033[0;33m Run the following for each user manually: ALTER USER 'laravel'@'localhost' identified via 'unix_socket'; \033[0m"
echo -e "\033[0;33m Run the following for each user manually: ALTER USER 'user_name'@'localhost' REQUIRE SSL; \033[0m"

chmod 660 /var/lib/mysql/server_audit.log
chown mysql:mysql /var/lib/mysql/server_audit.log

usermod -s /bin/false MySQL

chown -R mysql:mysql /etc/mysql/encryption
chmod 640 /etc/mysql/encryption/keyfile*

echo -e "\033[0;33m Ensure No Users Have Wildcard Hostnames. Use ALTER USER \033[0m"
echo -e "\033[0;33m Now you can enable encyption for any table in the desired database. Run this for each table : ALTER TABLE table_name ENCRYPTED=YES ENCRYPTION_KEY_ID=1; \033[0m"
echo "Done!"
