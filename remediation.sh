#!/bin/bash

# Not a complete list of remediation.

# Check if the required command-line arguments are provided
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <db_user> <db_password>"
    exit 1
fi

# Set permissions and ownership for /var/lib/mysql
chmod 750 /var/lib/mysql
chown mysql:mysql /var/lib/mysql

# Check if /var/log/mysql/mysql.log exists and set permissions and ownership
if [ -f /var/log/mysql/mysql.log ]; then
    chmod 660 /var/log/mysql/mysql.log
    chown mysql:mysql /var/log/mysql/mysql.log
fi

# Check if /usr/lib/mysql/plugin/ exists and set permissions and ownership
if [ -d /usr/lib/mysql/plugin/ ]; then
    chmod 550 /usr/lib/mysql/plugin/
    chown mysql:mysql /usr/lib/mysql/plugin/
fi

# Disable MariaDB Command History
ln -s /dev/null $HOME/.mysql_history

# Harden Usage for 'local_infile' on MariaDB Clients
mariadb --local-infile=0 --load-data-local-dir=/my/local/data

# Apply data-at-rest
mkdir -p /etc/mysql/encryption && (echo -n "1;" ; openssl rand -hex 32) | tee -a /etc/mysql/encryption/keyfile
openssl rand -hex 128 | tee -a /etc/mysql/encryption/keyfile.key
openssl enc -aes-256-cbc -md sha1 \
-pass file:/etc/mysql/encryption/keyfile.key \
-in /etc/mysql/encryption/keyfile \
-out /etc/mysql/encryption/keyfile.enc
rm /etc/mysql/encryption/keyfile
chown mysql:mysql -R /etc/mysql/encryption
chmod 640 /etc/mysql/encryption/keyfile*


# Install mariadb-plugin-cracklib-password-check
apt update
apt-get --assume-yes install mariadb-plugin-cracklib-password-check

# Run MariaDB Commands
# Get the command-line arguments
DB_USER="$1"
DB_PASSWORD="$2"

# Run the SQL commands
mysql -u $DB_USER -p$DB_PASSWORD -e "SET GLOBAL slow_query_log = 'OFF';"
mysql -u $DB_USER -p$DB_PASSWORD -e "SET GLOBAL general_log = 'OFF';"
mysql -u $DB_USER -p$DB_PASSWORD -e "SET GLOBAL sql_mode = 'STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';"
mysql -u $DB_USER -p$DB_PASSWORD -e "INSTALL SONAME 'simple_password_check';"
mysql -u $DB_USER -p$DB_PASSWORD -e "INSTALL SONAME 'cracklib_password_check';"
mysql -u $DB_USER -p$DB_PASSWORD -e "INSTALL SONAME 'server_audit';"
mysql -u $DB_USER -p$DB_PASSWORD -e "SET GLOBAL sql_mode ='STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';"
mysql -u $DB_USER -p$DB_PASSWORD -e "alter user 'root'@'localhost' identified via 'unix_socket'; set password for 'mysql'@'localhost' = 'invalid'; set password for 'mariadb.sys'@'localhost' = 'invalid';"
echo -e "\033[0;33m Run the following for each user manually: alter user 'laravel'@'localhost' identified via 'unix_socket'; \033[0m"
echo -e "\033[0;33m Run the following for each user manually: ALTER USER 'user_name'@'localhost' REQUIRE SSL; \033[0m"


chmod 660 /root/server_audit.log
chown mysql:mysql /root/server_audit.log


usermod -s /bin/false mysql

echo -e "\033[0;33m Ensure No Users Have Wildcard Hostnames. Use ALTER USER \033[0m"
echo -e "\033[0;33m Now you can enable encyption for any table in the desired database. (ALTER TABLE table_name ENCRYPTED=YES ENCRYPTION_KEY_ID=1;) \033[0m"
echo "Done!"
