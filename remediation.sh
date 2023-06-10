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



# Define the configuration entries
CONFIG_ENTRIES="
plugin_load_add = simple_password_check
simple_password_check = FORCE_PLUS_PERMANENT
simple_password_check_minimal_length = 14
plugin_load_add = cracklib_password_check
cracklib_password_check = FORCE_PLUS_PERMANENT
skip-symbolic-links = 1
skip-grant-tables = FALSE

plugin_load_add = file_key_management
file_key_management_filename = /etc/mysql/encryption/keyfile.enc
file_key_management_filekey = FILE:/etc/mysql/encryption/keyfile.key
# Binary Log Encryption
encrypt_binlog = ON
# Redo Log Encryption
innodb_encrypt_log = ON
# Encrypting Temporary Files
encrypt_tmp_files = ON
# You can configure InnoDB encryption to automatically have all new InnoDB
tables automatically encrypted, or specify encrypt per table.
innodb_encrypt_tables = ON
# Uncomment the line below if utilizing MariaDB built with OpenSSL
# file_key_management_encryption_algorithm = AES_CTR
"

# Add the entries to /etc/mysql/mariadb.cnf
echo "Adding entries to /etc/mysql/mariadb.cnf..."
echo "$CONFIG_ENTRIES" | tee -a /etc/mysql/mariadb.cnf > /dev/null

# Restart MariaDB service to apply the changes
echo "Restarting MariaDB service..."
service mariadb reload

usermod -s /bin/false mysql

echo -e "\033[0;33m Now you can enable encyption for any table in the desired database. (ALTER TABLE table_name ENCRYPTED=YES ENCRYPTION_KEY_ID=1;) \033[0m"
echo "Done!"
