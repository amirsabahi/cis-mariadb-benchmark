#!/bin/bash  

# MariaDB CIS Benchmark Audit Script

# Output file
output_file="maridb_audit_results.txt"

# Function to write audit results to the output file
write_to_file() {
    echo -e "$1" >> "$output_file"
}

# Check if the output file exists and delete it
if [ -f "$output_file" ]; then
    rm "$output_file"
fi

# Audit MariaDB configuration
write_to_file "==========================="
write_to_file "MariaDB CIS Benchmark Audit"
write_to_file "===========================\n"

#username="root"
#password="root"
#host="127.0.0.1"
#port="3308"

#exit 1

read -p "Enter the path to the MariaDB configuration file (e.g., /etc/mysql/my.cnf): " config_file

# Prompt for mariadbd startup command path
read -p "Enter the path to the mariadbd startup command: ( /usr/bin/mysql or /etc/bin/mysql): " mariadb_startup_command

# Prompt the user for MariaDB credentials
read -p "Enter MariaDB Username: " username
read -s -p "Enter MariaDB Password: " password
echo
read -p "Enter MariaDB Host (default: localhost): " host
host=${host:-localhost}
read -p "Enter MariaDB Port (default: 3306): " port
port=${port:-3306}

echo "CHECKING: 1.1 Operating System Level Configuration"
write_to_file "1.1 Operating System Level Configuration"

# Obtain the location of MariaDB database files
sql_query="SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM information_schema.global_variables
WHERE (VARIABLE_NAME LIKE '%dir' OR VARIABLE_NAME LIKE '%file') AND
(VARIABLE_NAME NOT LIKE '%core%' AND VARIABLE_NAME <> 'local_infile' AND VARIABLE_NAME <> 'relay_log_info_file')
ORDER BY VARIABLE_NAME;"

datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "$sql_query" | grep 'DATADIR' | awk '{print $2}')

# Check if datadir result is empty
if [ -z "$datadir_result" ]; then
  echo "Failed to obtain datadir location."

fi

# Execute df command for datadir location
df_output=$(df -h "$datadir_result" | grep -vE "^Filesystem|/var|/usr|/$")

# Display the df output
if [ -nz "$df_output" ]; then
echo "$df_output"
  echo "Failed to obtain datadir location."
  write_to_file "The output returned from the df command above should not include root (/), /var, or /usr."
else
   write_to_file "PASS: 1.1 Place Databases on Non-System Partitions (Manual)"
fi

write_to_file "\n"
echo "CHECKING: 1.2 Use Dedicated Least Privileged Account for MariaDB Daemon/Service (Automated)"
write_to_file  "1.2 Use Dedicated Least Privileged Account for MariaDB Daemon/Service (Automated)"
# Execute the command to assess the recommendation
output=$(ps -ef | egrep "^mysql.*$")

# Check if any lines are returned
if [ -z "$output" ]; then
  write_to_file "FAIL: No MySQL/MariaDB process found."
else
  write_to_file "PASS: MySQL/MariaDB process is running."
fi

# Check sudo privileges for the MariaDB user
sudo_output=$(sudo -l -U mysql 2>/dev/null)

# Check if sudo privileges exist
if [ -n "$sudo_output" ]; then
  write_to_file "FAIL: Sudo Privileges: Sudo privileges are available for the MariaDB user."
else
  write_to_file "PASS: Sudo Privileges: No sudo privileges found for the MariaDB user."
fi

write_to_file "\n"
echo "CHECKING: 1.3 Disable MariaDB Command History (Automated)"
write_to_file  "1.3 Disable MariaDB Command History (Automated)"

# Find .mysql_history files in /home directory
home_files=$(find /home -name ".mysql_history")

# Find .mysql_history files in /root directory
root_files=$(find /root -name ".mysql_history")

# Combine the file lists
all_files="$home_files"$'\n'"$root_files"

# Check if any .mysql_history files are found
if [ -z "$all_files" ]; then
  write_to_file "No .mysql_history files found."

fi

# Iterate over each file and check if it is symbolically linked to /dev/null
for file in $all_files; do
  if [ -L "$file" ] && [ "$(readlink "$file")" == "/dev/null" ]; then
    write_to_file "PASS: File: $file is symbolically linked to /dev/null"
  else
    write_to_file "FAIL: File: $file is not symbolically linked to /dev/null"
  fi

write_to_file "\n"
echo "CHECKING: 1.4 Verify That the MYSQL_PWD Environment Variable is Not in Use (Automated)"
write_to_file  "1.4 Verify That the MYSQL_PWD Environment Variable is Not in Use (Automated)"
# Verify That the MYSQL_PWD Environment Variable is Not in Use
output=$(grep MYSQL_PWD /proc/*/environ | grep -vE "^/proc/$$")

# Check if any entries are returned
if [ -z "$output" ]; then
  write_to_file "PASS: MYSQL_PWD is not set for any process."
else
  write_to_file "FAIL: MYSQL_PWD is set for the following process(es):"
  write_to_file "$output"
fi

write_to_file "\n"
echo "CHECKING: 1.5 Ensure Interactive Login is Disabled (Automated)"
write_to_file  "1.5 Ensure Interactive Login is Disabled (Automated)"
# Execute the command to assess the recommendation
output=$(getent passwd mysql | egrep "^.*[\/bin\/false|\/sbin\/nologin]$")
# Check if any output is returned
if [ -z "$output" ]; then
  write_to_file "FAIL: Interactive login is not disabled for the mysql user."
else
  write_to_file "PASS: Interactive login is disabled for the mysql user."
fi

write_to_file "\n"
echo "CHECKING: 1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles (Automated)"
write_to_file  "1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles(Automated)"
# Execute the command to verify MYSQL_PWD in users' profiles
output=$(grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 2>/dev/null)

# Check if any lines are returned
if [ -z "$output" ]; then
  write_to_file "PASS: MYSQL_PWD is not set in users' profiles."
else
  write_to_file "FAIL: MYSQL_PWD is set in the following user profiles:"
  write_to_file "$output"
fi

write_to_file "\n"
echo "CHECKING: 1.7 Ensure MariaDB is Run Under a Sandbox Environment(Manual)"
write_to_file  "1.7 Ensure MariaDB is Run Under a Sandbox Environment(Manual)\n"

# Step 1: Check chroot
chroot_path=$(cat /etc/mysql/my.cnf | egrep -o '(?<=^chroot=).+$')

if [ -z "$chroot_path" ]; then
  write_to_file "FAIL: 'chroot' is not in use.\n"
else
  write_to_file "PASS: 'chroot' is set to $chroot_path.\n"
fi

# Step 2: Check systemd
systemd_status=$(systemctl status mariadb.service)

if echo "$systemd_status" | grep -q "(root)"; then
  write_to_file "PASS: MariaDB is managed by systemd.\n"
else
  write_to_file "FAIL: MariaDB is not managed by systemd.\n"
fi

systemd_status=$(systemctl status mysql.service)
if echo "$systemd_status" | grep -q "(root)"; then
  write_to_file "PASS: MySQL(MariaDB) is managed by systemd.\n"
else
  write_to_file "FAIL: MySQL(MariaDB) is not managed by systemd.\n"
fi

#
# Step 3: Check Docker
docker_version=$(docker -v 2>&1)

if echo "$docker_version" | grep -q "Docker version"; then
  write_to_file "PASS: Docker is installed."

  # Check MariaDB image in Docker
  mariadb_image=$(sudo docker images -q mariadb:latest)

  if [ -z "$mariadb_image" ]; then
    write_to_file "FAIL: MariaDB image is not found in Docker."
  else
    write_to_file "PASS: MariaDB image exists in Docker."

    # Check MariaDB container in Docker
    mariadb_container=$(sudo docker ps -q -f ancestor=mariadb:latest)

    if [ -z "$mariadb_container" ]; then
      write_to_file "FAIL: MariaDB container is not running in Docker."
    else
      write_to_file "PASS: MariaDB container is running in Docker."
    fi
  fi
else
  write_to_file "FAIL: Docker is not installed."
fi

write_to_file "\n"
echo "CHECKING: 2.1.5 Point-in-Time Recovery (Automated)"
write_to_file  "2.1.5 Point-in-Time Recovery (Automated))\n"
# Check if binlogs are enabled
binlog_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -e "SHOW VARIABLES LIKE 'log_bin';" | awk '{print $2}')

if [ "$binlog_status" = "ON" ]; then
  write_to_file "PASS: Binlogs are enabled.\n"
else
  write_to_file "FAIL: Binlogs are not enabled.\n"
fi

# Check if there is a restore procedure
restore_procedure=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW PROCEDURE STATUS WHERE Name = 'restore_backup';" | awk 'NR>1')

if [ -n "$restore_procedure" ]; then
  write_to_file "PASS: Restore procedure 'restore_backup' exists.\n"
else
  write_to_file "FAIL: Restore procedure 'restore_backup' does not exist.\n"
fi

# Check if binlog_expire_logs_seconds is set
expire_logs_seconds=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'binlog_expire_logs_seconds';" | awk 'NR>1')

if [ "$expire_logs_seconds" != "0" ]; then
  write_to_file "PASS: binlog_expire_logs_seconds is set to $expire_logs_seconds.\n"
else
  write_to_file "FAIL: binlog_expire_logs_seconds is set to 0.\n"
fi

write_to_file "\n"
echo "CHECKING: 2.4 Do Not Reuse Usernames (Manual)"
write_to_file  "2.4 Do Not Reuse Usernames (Manual)\n"

sql_query="SELECT host, user, plugin,
IF(plugin = 'mysql_native_password',
'WEAK SHA1', 'STRONG SHA2') AS HASHTYPE
FROM mysql.user WHERE user NOT IN
('mysql.infoschema', 'mysql.session', 'mysql.sys') AND
plugin NOT LIKE 'auth%' AND plugin <> 'mysql_no_login' AND
LENGTH(authentication_string) > 0
ORDER BY plugin;"

write_to_file "Each user (excluding mysql reserved users) should be linked to one of these:
• system accounts
• a person
• an application"
datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "$sql_query")
write_to_file $datadir_result

write_to_file "\n"
echo "CHECKING: 2.6 Ensure 'password_lifetime' is Less Than or Equal to '365'(Automated)"
write_to_file  "2.6 Ensure 'password_lifetime' is Less Than or Equal to '365'(Automated)\n"

# Check global password lifetime
global_lifetime=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'default_password_lifetime';")

if [ $global_lifetime -gt 365 ]; then
  write_to_file "FAIL: Global password lifetime is greater than 365."
else
  write_to_file "PASS: Global password lifetime is less than or equal to 365, or not configured."
fi

# Check each user account's password expiration
password_expiration_query="WITH password_expiration_info AS (
SELECT User, Host,
IF(
IFNULL(JSON_EXTRACT(Priv, '$.password_lifetime'), -1) = -1,
@@global.default_password_lifetime,
JSON_EXTRACT(Priv, '$.password_lifetime')
) AS password_lifetime,
JSON_EXTRACT(Priv, '$.password_last_changed') AS password_last_changed
FROM mysql.global_priv
)
SELECT pei.User, pei.Host, pei.password_lifetime,
FROM_UNIXTIME(pei.password_last_changed) AS password_last_changed_datetime,
FROM_UNIXTIME(pei.password_last_changed + (pei.password_lifetime * 60 * 60 * 24)) AS password_expiration_datetime
FROM password_expiration_info pei
WHERE pei.password_lifetime != 0 AND pei.password_last_changed IS NOT NULL
UNION
SELECT pei.User, pei.Host, pei.password_lifetime,
FROM_UNIXTIME(pei.password_last_changed) AS password_last_changed_datetime,
0 AS password_expiration_datetime
FROM password_expiration_info pei
WHERE pei.password_lifetime = 0 OR pei.password_last_changed IS NULL;"

user_password_expiration=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$password_expiration_query")

# Write user password expiration information to the file
write_to_file "\nUser Password Expiration:"

if [ -n "$user_password_expiration" ]; then
  write_to_file "$user_password_expiration"
else
  write_to_file "No user accounts found."
fi

write_to_file "\n"
echo "CHECKING: 2.7 Lock Out Accounts if Not Currently in Use (Manual)"
write_to_file  "2.7 Lock Out Accounts if Not Currently in Use (Manual)\n"

# Check account lock status
lock_status_query="SELECT CONCAT(user, '@', host, ' => ', JSON_DETAILED(priv)) FROM mysql.global_priv;"

account_lock_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$lock_status_query")

# Write account lock status to the file
write_to_file "Accounts not in use and MariaDB Reserved accounts should show as account_locked:true \n"
write_to_file "Account Lock Status:"

if [ -n "$account_lock_status" ]; then
  write_to_file "$account_lock_status"
else
  write_to_file "No accounts found."
fi

write_to_file "\n"
echo "CHECKING:2.8 Ensure Socket Peer-Credential Authentication is Used Appropriately (Manual)"
write_to_file  "2.8 Ensure Socket Peer-Credential Authentication is Used Appropriately (Manual))\n"

# Check if unix_socket plugin is enabled
plugin_status_query="SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME = 'unix_socket';"

plugin_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$plugin_status_query")

# Write plugin status to the file
write_to_file "If PLUGIN_STATUS is ACTIVE and the organization does not allow use of this feature, this is a fail.\n"
write_to_file "Plugin Status:"

if [ -n "$plugin_status" ]; then
  write_to_file "$plugin_status\n"
else
  write_to_file "Plugin not found.\n"
fi

# Check users who can use unix_socket
user_unix_socket_query="SELECT CONCAT(user, '@', host, ' => ', JSON_DETAILED(priv)) FROM mysql.global_priv WHERE JSON_CONTAINS(priv, '{"plugin":"unix_socket"}', '$.auth_or');"

user_unix_socket=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$user_unix_socket_query")

# Write users who can use unix_socket to the file
write_to_file "If host is not the localhost or an unauthorized user is listed, this is a fail."
write_to_file "\nUsers with unix_socket privilege:"

if [ -n "$user_unix_socket" ]; then
  write_to_file "$user_unix_socket\n"
else
  write_to_file "No users found.\n\n"
fi


write_to_file "\n"
echo "CHECKING: 2.9 Ensure MariaDB is Bound to an IP Address (Automated)"
write_to_file  "2.9 Ensure MariaDB is Bound to an IP Address (Automated)\n"
# Run SQL statement to check bind_address variable
bind_address_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'bind_address';"

bind_address_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$bind_address_query")

# Write results to the file
write_to_file "Any empty VARIABLE_VALUE implies a fail."
write_to_file "\nBind Address Audit:"

if [ -n "$bind_address_result" ]; then
  write_to_file "$bind_address_result"
else
  write_to_file "No results found."
fi

write_to_file "\n"
echo "CHECKING: 2.10 Limit Accepted Transport Layer Security (TLS) Versions (Automated)"
write_to_file  "2.10 Limit Accepted Transport Layer Security (TLS) Versions (Automated))\n"
# Check TLS versions
tls_versions_query="select @@tls_version;"

tls_versions_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$tls_versions_query")

# Write results to the file
write_to_file "If the list includes TLSv1 and/or TLSv1.1, this is a fail."
write_to_file "\nTLS Version Audit:"

if [ -n "$tls_versions_result" ]; then
  write_to_file "$tls_versions_result"
else
  write_to_file "No results found.\n"
fi

write_to_file "\n"
echo "CHECKING: 2.11 Require Client-Side Certificates (X.509) (Automated)"
write_to_file  "2.11 Require Client-Side Certificates (X.509) (Automated)\n"

# Check SSL type for users
ssl_type_query="SELECT user, host, ssl_type FROM mysql.user WHERE user NOT IN ('mysql', 'root', 'mariadb.sys');"

ssl_type_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$ssl_type_query")

# Write results to the file
"If ssl_type returns X509, client-side certificate details must be provided to connect."
write_to_file write_to_file "Client-Side Certificate Audit:"

if [ -n "$ssl_type_result" ]; then
  write_to_file "$ssl_type_result"
else
  write_to_file "No results found.\n"
fi

write_to_file "\n"
echo "CHECKING: 2.12 Require Client-Side Certificates (X.509) (Automated)"
write_to_file  "2.12 Require Client-Side Certificates (X.509) (Automated)\n"

# Run the SQL statement to check SSL ciphers
ssl_ciphers_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'ssl_cipher';"

ssl_ciphers_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$ssl_ciphers_query")

# Write results to the file
write_to_file "SSL Ciphers Audit:"

if [ -n "$ssl_ciphers_result" ]]; then
  write_to_file "$ssl_ciphers_result"
else
  write_to_file "No results found.\n"
fi

# Check if SSL ciphers are empty or contain unapproved ciphers
approved_ciphers=("cipher1" "cipher2" "cipher3")  # Add your approved ciphers here

IFS=$'\n'
for cipher in $ssl_ciphers_result; do
  cipher_name=$(echo "$cipher" | awk '{print $2}')
  
  if [ -z "$cipher_name" ]]; then
    write_to_file "FAIL: SSL ciphers are empty."
  elif [ ! " ${approved_ciphers[@]} " =~ " $cipher_name " ]]; then
    write_to_file "FAIL: Unapproved cipher found: $cipher_name"
  else
    write_to_file "PASS: $cipher_name"
  fi
done

# Reset IFS
unset IFS

write_to_file "\n"

write_to_file "Escaped audits 2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7, 2.2, 2.3, 2.5, 2.8\n"
echo "Escaped audits 2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7, 2.2, 2.3, 2.5, 2.8"

write_to_file "\n"

write_to_file "Do you have a solid backup plan? This script do not check all the 2.1 Backup and Disaster Recovery.\n Use following link to learn more: https://mariadb.com/kb/en/using-encryption-and-compression-tools-with-mariabackup/"

echo "Do you have a solid backup plan? This script do not check all the 2.1 Backup and Disaster Recovery.\n Use following link to learn more: https://mariadb.com/kb/en/using-encryption-and-compression-tools-with-mariabackup/"

write_to_file "\n"
echo "CHECKING: 3.1 Ensure 'datadir' Has Appropriate Permissions (Automated)"
write_to_file  "3.1 Ensure 'datadir' Has Appropriate Permissions (Automated))\n"

# Execute the SQL statement to determine the value of datadir
datadir_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME LIKE 'DATADIR';"

datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$datadir_query")

# Write results to the file
write_to_file "datadir Permissions Audit:"

if [[ -n "$datadir_result" ]]; then
  write_to_file "$datadir_result"
  
  # Extract the datadir path from the result
  datadir_path=$(echo "$datadir_result" | awk '{print $2}')
  
  # Execute the command to check datadir permissions
  permissions_check=$(sudo ls -ld "$datadir_path" | grep "drwxr-x---.*mysql.*mysql")
  
  if [[ -z "$permissions_check" ]]; then
    write_to_file "FAIL: 'datadir' does not have appropriate permissions."
  else
    write_to_file "PASS: 'datadir' has appropriate permissions."
  fi
else
  write_to_file "No 'datadir' value found."
  write_to_file "FAIL: Unable to determine 'datadir' path."
fi

write_to_file "\n"
echo "CHECKING: 3.2 Ensure 'log_bin_basename' Files Have AppropriatePermissions (Automated)"
write_to_file  "3.2 Ensure 'log_bin_basename' Files Have AppropriatePermissions (Automated)\n"

# Execute the SQL statement to determine the value of log_bin_basename
log_bin_basename_query="show variables like 'log_bin_basename';"

log_bin_basename_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$log_bin_basename_query")

# Write results to the file
write_to_file "log_bin_basename Permissions Audit:"

if [[ -n "$log_bin_basename_result" ]]; then
  write_to_file "$log_bin_basename_result"
  
  # Extract the log_bin_basename value from the result
  log_bin_basename=$(echo "$log_bin_basename_result" | awk '{print $2}')
  
  # Execute the command to check log_bin_basename file permissions
  permissions_check=$(ls -l | egrep '^-(?![r|w]{2}-[r|w]{2}----.*mysql\s*mysql).*'"$log_bin_basename"'.*$')
  
  if [[ -z "$permissions_check" ]]; then
    write_to_file "PASS: 'log_bin_basename' files have appropriate permissions."
  else
    write_to_file "FAIL: Non-compliant 'log_bin_basename' file permissions found:"
    write_to_file "$permissions_check"
  fi
else
  write_to_file "No 'log_bin_basename' value found."
  write_to_file "FAIL: Unable to determine 'log_bin_basename'."
fi

write_to_file "\n"
echo "CHECKING: 3.3 Ensure 'log_error' Has Appropriate Permissions (Automated)"
write_to_file  "3.3 Ensure 'log_error' Has Appropriate Permissions (Automated)\n"

# Execute the SQL statement to determine the value of log_error
log_error_query="show variables like 'log_error';"

log_error_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$log_error_query")

# Write results to the file
write_to_file "log_error Permissions Audit:"

if [[ -n "$log_error_result" ]]; then
  write_to_file "$log_error_result"
  
  # Extract the log_error value from the result
  log_error=$(echo "$log_error_result" | awk '{print $2}')
  
  # Execute the command to check log_error file permissions
  permissions_check=$(ls -l "$log_error" | grep '^-rw-------.*mysql.*mysql.*$')
  
  if [[ -z "$permissions_check" ]]; then
    write_to_file "PASS: 'log_error' file has appropriate permissions."
  else
    write_to_file "FAIL: Non-compliant 'log_error' file permissions found:"
    write_to_file "$permissions_check"
  fi
else
  write_to_file "No 'log_error' value found."
  write_to_file "FAIL: Unable to determine 'log_error'."
fi

write_to_file "\n"
echo "CHECKING: 3.4 Ensure 'slow_query_log' Has Appropriate Permissions (Automated)"
write_to_file  "3.4 Ensure 'slow_query_log' Has Appropriate Permissions (Automated)\n"

# Execute the SQL statement to determine the value of slow_query_log
slow_query_log_query="show variables like 'slow_query_log';"

slow_query_log_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$slow_query_log_query")

# Write results to the file
write_to_file "slow_query_log Permissions Audit:"

if [[ -n "$slow_query_log_result" ]]; then
  write_to_file "$slow_query_log_result"
  
  # Extract the slow_query_log value from the result
  slow_query_log=$(echo "$slow_query_log_result" | awk '{print $2}')
  
  # Check if slow_query_log is enabled or disabled
  if [[ "$slow_query_log" == "OFF" ]]; then
    write_to_file "Slow query log is disabled."
    
    # Remove any old slow query log files
    rm -f "$slow_query_log"
    
    write_to_file "Old slow query log files removed."
  else
    # Execute the SQL statement to determine the location of slow_query_log_file
    slow_query_log_file_query="show variables like 'slow_query_log_file';"

    slow_query_log_file_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$slow_query_log_file_query")

    if [[ -n "$slow_query_log_file_result" ]]; then
      write_to_file "$slow_query_log_file_result"
      
      # Extract the slow_query_log_file value from the result
      slow_query_log_file=$(echo "$slow_query_log_file_result" | awk '{print $2}')
      
      # Execute the command to check slow_query_log_file permissions
      permissions_check=$(ls -l "$slow_query_log_file" | grep '^-rw-------.*mysql.*mysql.*$')
      
      if [[ -z "$permissions_check" ]]; then
        write_to_file "FAIL: Non-compliant 'slow_query_log_file' permissions found:"
        write_to_file "$permissions_check"
      else
        write_to_file "PASS: 'slow_query_log_file' has appropriate permissions."
      fi
    else
      write_to_file "No 'slow_query_log_file' value found."
      write_to_file "FAIL: Unable to determine 'slow_query_log_file'."
    fi
  fi
else
  write_to_file "No 'slow_query_log' value found."
  write_to_file "FAIL: Unable to determine 'slow_query_log'."
fi

write_to_file "\n"
echo "CHECKING: 3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions (Automated)"
write_to_file  "3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions (Automated)\n"

# Execute the SQL statement to determine the value of relay_log_basename
relay_log_basename_query="show variables like 'relay_log_basename';"

relay_log_basename_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$relay_log_basename_query")

# Write results to the file
write_to_file "relay_log_basename Permissions Audit:"

if [[ -n "$relay_log_basename_result" ]]; then
  write_to_file "$relay_log_basename_result"
  
  # Extract the relay_log_basename value from the result
  relay_log_basename=$(echo "$relay_log_basename_result" | awk '{print $2}')
  
  # Execute the command to check relay_log_basename file permissions
  permissions_check=$(ls -l | egrep "^-(?![r|w]{2}-[r|w]{2}----.*mysql\s*mysql).*${relay_log_basename}.*$")

  if [[ -z "$permissions_check" ]]; then
    write_to_file "PASS: 'relay_log_basename' files have appropriate permissions."
  else
    write_to_file "FAIL: Non-compliant 'relay_log_basename' file permissions found:"
    write_to_file "$permissions_check"
  fi
else
  write_to_file "No 'relay_log_basename' value found."
  write_to_file "FAIL: Unable to determine 'relay_log_basename'."
fi

write_to_file "\n"
echo "CHECKING: 3.6 Ensure 'general_log_file' Has Appropriate Permissions (Automated))"
write_to_file  "3.6 Ensure 'general_log_file' Has Appropriate Permissions (Automated))\n"

# Execute the SQL statement to determine the values of general_log and general_log_file
general_log_query="select @@general_log, @@general_log_file;"

general_log_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$general_log_query")

# Write results to the file
write_to_file "general_log_file Permissions Audit:"

if [[ -n "$general_log_result" ]]; then
  write_to_file "$general_log_result"
  
  # Extract the general_log and general_log_file values from the result
  general_log=$(echo "$general_log_result" | awk '{print $1}')
  general_log_file=$(echo "$general_log_result" | awk '{print $2}')
  
  # Check if the general log is enabled or disabled
  if [[ "$general_log" == "0" || "$general_log" == "OFF" ]]; then
    if [[ -f "$general_log_file" ]]; then
      # General log is disabled, remove the old general log file
      rm "$general_log_file"
      write_to_file "General log file removed."
    else
      write_to_file "General log is disabled. No log file found."
    fi
  elif [[ "$general_log" == "1" || "$general_log" == "ON" ]]; then
    # General log is enabled, check the file permissions
    permissions_check=$(ls -l "$general_log_file" | grep '^-rw-------.*mysql.*mysql')
  
    if [[ -z "$permissions_check" ]]; then
      write_to_file "FAIL: Non-compliant 'general_log_file' permissions found:"
      write_to_file "$permissions_check"
    else
      write_to_file "PASS: 'general_log_file' has appropriate permissions."
    fi
  else
    write_to_file "Unknown general_log value: $general_log"
    write_to_file "Unable to assess 'general_log_file' permissions."
  fi
else
  write_to_file "No 'general_log' or 'general_log_file' values found."
  write_to_file "FAIL: Unable to determine 'general_log' and 'general_log_file'."
fi

write_to_file "\n"
echo "CHECKING: 3.7 Ensure SSL Key Files Have Appropriate Permissions (Automated)"
write_to_file  "3.7 Ensure SSL Key Files Have Appropriate Permissions (Automated)\n"

# Execute the SQL statement to retrieve SSL key files
ssl_key_files=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE REGEXP_INSTR(VARIABLE_NAME, '^.*ssl_(ca|capath|cert|crl|crlpath|key)$') AND VARIABLE_VALUE <> '';" | tail -n +2)

# Perform the permissions audit for each SSL key file
write_to_file "SSL Key Files Permissions Audit:"

while IFS= read -r ssl_file; do
  # Check if the SSL key file exists
  if [[ -f "$ssl_file" ]]; then
    permissions_check=$(ls -l "$ssl_file" | egrep '^-.(?!r-{8}.*mysql\s*mysql).*$')
  
    if [[ -z "$permissions_check" ]]; then
      write_to_file "PASS: SSL key file has appropriate permissions: $ssl_file"
    else
      write_to_file "FAIL: Non-compliant permissions found for SSL key file: $ssl_file"
      write_to_file "$permissions_check"
    fi
  else
    write_to_file "SSL key file does not exist: $ssl_file"
  fi
done <<< "$ssl_key_files"

write_to_file "\n"
echo "CHECKING: 3.8 Ensure Plugin Directory Has Appropriate Permissions (Automated)"
write_to_file  "3.8 Ensure Plugin Directory Has Appropriate Permissions (Automated)\n"

# Retrieve plugin directory value from MySQL
plugin_dir=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "show variables where variable_name = 'plugin_dir'" | awk '/plugin_dir/ {print $2}')

# Check permissions and ownership of the plugin directory
ls -ld "$plugin_dir" | grep -E "dr-xr-x---|dr-xr-xr--" | grep "plugin"

# Check if there was any output from the command
if [ $? -eq 0 ]; then
  write_to_file "PASS: Plugin directory has appropriate permissions."
else
  write_to_file "FAIL: Plugin directory does not have appropriate permissions."
fi

write_to_file "\n"
echo "CHECKING: 3.9 Ensure 'server_audit_file_path' Has Appropriate Permissions (Automated)"
write_to_file  "3.9 Ensure 'server_audit_file_path' Has Appropriate Permissions (Automated)\n"

# Retrieve 'server_audit_file_path' value from MySQL
server_audit_file_path=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "show global variables where variable_name='server_audit_file_path'" | awk '/server_audit_file_path/ {print $2}')

# Check if 'server_audit_file_path' value is empty
if [[ -z "$server_audit_file_path" ]]; then
  write_to_file "FAIL: Auditing is not installed."
fi

# Check permissions and ownership of the server audit file path
ls -l "$server_audit_file_path" | grep -E "^-([rw-]{2}-){2}---[ \t]*[0-9][ \t]*mysql[ \t]*mysql.*$"

# Check if there was any output from the command
if [ $? -eq 0 ]; then
  write_to_file "PASS: 'server_audit_file_path' has appropriate permissions."
else
  write_to_file "FAIL: 'server_audit_file_path' does not have appropriate permissions."
fi

write_to_file "\n"
echo "CHECKING: 3.10 Ensure File Key Management Encryption Plugin files have appropriate permissions (Automated)"
write_to_file  "3.10 Ensure File Key Management Encryption Plugin files have appropriate permissions (Automated)\n"
# Step 1: Find the file_key_management_filename value
file_key_management_filename=$(grep -Po '(?<=file_key_management_filename=).+$' /etc/mysql/mariadb.cnf)

# Check if file_key_management_filename value is empty
if [[ -z "$file_key_management_filename" ]]; then
  write_to_file "FAIL: File Key Management Encryption plugin is not configured."
fi

# Verify permissions for file_key_management_filename
file_key_management_filename_permissions=$(stat -c "%a %U:%G" "$file_key_management_filename")

# Check if permissions are 750 or more restrictive for file_key_management_filename
if [[ "$file_key_management_filename_permissions" =~ ^(750|[0-6]{2}[0-7]{1}[0-7]{1})\ mysql:mysql$ ]]; then
  write_to_file "PASS: 'file_key_management_filename' has appropriate permissions."
else
  write_to_file "FAIL: 'file_key_management_filename' does not have appropriate permissions."
fi

# Step 2: Find the file_key_management_filekey value
file_key_management_filekey=$(grep -Po '(?<=file_key_management_filekey=).+$' /etc/mysql/mariadb.cnf)

# Verify permissions for file_key_management_filekey
file_key_management_filekey_permissions=$(stat -c "%a %U:%G" "$file_key_management_filekey")

# Check if permissions are 750 or more restrictive for file_key_management_filekey
if [[ "$file_key_management_filekey_permissions" =~ ^(750|[0-6]{2}[0-7]{1}[0-7]{1})\ mysql:mysql$ ]]; then
  write_to_file "PASS: 'file_key_management_filekey' has appropriate permissions."
else
  write_to_file "FAIL: 'file_key_management_filekey' does not have appropriate permissions."
fi

write_to_file "\n"
echo "CHECKING: 4.1 Ensure the Latest Security Patches are Applied (Manual)"
write_to_file  "4.1 Ensure the Latest Security Patches are Applied (Manual)\n"

# Execute SQL statement to identify MariaDB server version
mariadb_version=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -N -B -e "SHOW VARIABLES WHERE Variable_name LIKE 'version';" | awk '{print $2}')

# Compare the version with security announcements
latest_version="11.2"  # Update this with the latest version announced

if [[ "$mariadb_version" == "$latest_version" ]]; then
  write_to_file "PASS: MariaDB server is up to date."
else
  write_to_file "FAIL: MariaDB server may not have the latest security patches applied. Current installed version is: $mariadb_version"
fi


write_to_file "\n"
echo "4.2 Ensure Example or Test Databases are Not Installed on Production Servers (Automated)"
write_to_file  "4.2 Ensure Example or Test Databases are Not Installed on Production Servers (Automated)\n"

# Execute SQL statement to determine if test database is present
result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -N -B -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql', 'information_schema', 'sys', 'performance_schema');")

if [[ $result -gt 0 ]]; then
  write_to_file "FAIL: Test or example databases are present on the server."
else
  write_to_file "PASS: No test or example databases found."
fi


write_to_file "\n"
echo "4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF' (Automated)"
write_to_file  "4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF' (Automated)"

# Check mariadbd startup command line for --allow-suspicious-udfs
if grep -q -- '--allow-suspicious-udfs' "$mariadb_startup_command"; then
  write_to_file "FAIL: 'allow-suspicious-udfs' is specified in the mariadbd startup command line."
else
  write_to_file "PASS: 'allow-suspicious-udfs' is not specified in the mariadbd startup command line."
fi

# Check MariaDB configuration for 'allow-suspicious-udfs'
result=$(my_print_defaults mysqld | grep -c 'allow-suspicious-udfs')

if [[ $result -eq 0 ]]; then
  write_to_file "PASS: 'allow-suspicious-udfs' is set to 'OFF' in the MariaDB configuration."
else
  write_to_file "FAIL: 'allow-suspicious-udfs' is not set to 'OFF' in the MariaDB configuration."
fi

write_to_file "\n"
write_to_file "4.4 Harden Usage for 'local_infile' on MariaDB Clients (Automated)"
echo   "4.4 Harden Usage for 'local_infile' on MariaDB Clients (Automated)\n"
# Check MariaDB client version
client_version=$(mariadb --version | awk '{print $5}')
required_version="10.2.0"
write_to_file "NOTICE: MariaDB client version should be $required_version or higher. Current version is: $client_version"

# Check local_infile variable
local_infile_value=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -e "SHOW VARIABLES WHERE Variable_name = 'local_infile'" | grep local_infile | awk '{print $2}')

if [[ $local_infile_value == "OFF" || $local_infile_value == "0" ]]; then
  write_to_file "PASS: local_infile is disabled or not in use."
else
  write_to_file "FAIL: local_infile should be disabled or not in use."
fi

write_to_file "\n"
echo "4.5 Ensure mariadb is Not Started With 'skip-grant-tables' (Automated)"
write_to_file  "3.5 Ensure mariadb is Not Started With 'skip-grant-tables' (Automated)\n"

skip_grant_tables=$(grep -E -i "skip[_-]grant[_-]tables" "$config_file" | grep -v "#" | awk -F "=" '{print $2}' | tr '[:upper:]' '[:lower:]')

if [[ -z $skip_grant_tables || $skip_grant_tables == "false" ]]; then
  write_to_file "PASS: MariaDB is not started with 'skip-grant-tables'."
else
  write_to_file "FAIL: MariaDB is started with 'skip-grant-tables'."
fi


write_to_file "\n"
echo "4.6 Ensure Symbolic Links are Disabled (Automated)"
write_to_file  "4.6 Ensure Symbolic Links are Disabled (Automated)\n"
# Execute the SQL statement to check the value of 'have_symlink'
have_symlink=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'have_symlink';" | awk '{print $2}')

if [[ $have_symlink == "DISABLED" ]]; then
  write_to_file "PASS: Symbolic links are disabled."
else
  write_to_file "FAIL: Symbolic links are not disabled."
fi


write_to_file "\n"
echo "4.7 Ensure the 'secure_file_priv' is Configured Correctly (Automated)"
write_to_file  "4.7 Ensure the 'secure_file_priv' is Configured Correctly (Automated)\n"
# Execute the SQL statement to check the value of 'secure_file_priv'
secure_file_priv=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv';" | awk 'NR>1 {print $2}')

if [[ -z "$secure_file_priv" ]]; then
  write_to_file "FAIL: 'secure_file_priv' is set to an empty string."
elif [[ "$secure_file_priv" == "NULL" ]]; then
  write_to_file "PASS: 'secure_file_priv' is disabled."
else
  write_to_file "PASS: 'secure_file_priv' is configured with a valid path: $secure_file_priv"
fi



write_to_file "\n"
echo "4.8 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' (Automated)"
write_to_file "4.8 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' (Automated)\n"
# Execute the SQL statement to check the value of 'sql_mode'
sql_mode=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'sql_mode';" | awk 'NR>1 {print $2}')

if [[ "$sql_mode" == *"STRICT_ALL_TABLES"* ]]; then
  write_to_file "PASS: 'sql_mode' contains 'STRICT_ALL_TABLES'."
else
  write_to_file "FAIL: 'sql_mode' does not contain 'STRICT_ALL_TABLES'."
fi



write_to_file "\n"
echo "4.9 Enable data-at-rest encryption in MariaDB (Automated)"
write_to_file  "4.9 Enable data-at-rest encryption in MariaDB (Automated)\n"
# Check if data-at-rest encryption is enabled
encryption_enabled=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE variable_name LIKE '%ENCRYPT%';" | awk 'NR>1 {print $1}')

if [[ "$encryption_enabled" == "OFF" ]]; then
  write_to_file "FAIL: Data-at-rest encryption is not enabled."
else
  write_to_file "PASS: Data-at-rest encryption is enabled."
  
  # List encrypted tablespaces
  encrypted_tablespaces=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT SPACE, NAME FROM INFORMATION_SCHEMA.INNODB_TABLESPACES_ENCRYPTION;" | awk 'NR>1 {print $1,$2}')

  if [[ -z "$encrypted_tablespaces" ]]; then
    write_to_file "FAIL: No encrypted tablespaces found."
  else
    write_to_file "Encrypted tablespaces:"
    write_to_file "$encrypted_tablespaces"
  fi
fi

write_to_file "\n"
echo "5.1 Ensure Only Administrative Users Have Full Database Access (Manual)"
write_to_file  "5.1 Ensure Only Administrative Users Have Full Database Access (Manual)\n"
# Execute the SQL statement to check user privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT * FROM information_schema.user_privileges WHERE grantee NOT LIKE \"\'mysql.%localhost'\'\";")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: Only administrative users have full database access."
else
  write_to_file "FAIL: Non-administrative users have full database access."
  write_to_file "Non-administrative users:"
  write_to_file "$query_result"
fi

write_to_file "\n"
echo "5.2 Ensure 'FILE' is Not Granted to Non-Administrative Users  (Manual)"
write_to_file  "5.2 Ensure 'FILE' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check FILE privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'FILE';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'FILE' privilege is not granted to non-administrative users."
else
  write_to_file "FAIL: 'FILE' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'FILE' privilege:"
  write_to_file "$query_result"
fi


write_to_file "\n"
echo "5.3 Ensure 'PROCESS' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.3 Ensure 'PROCESS' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check PROCESS privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'PROCESS';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'PROCESS' privilege is not granted to non-administrative users."
else
  write_to_file "FAIL: 'PROCESS' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'PROCESS' privilege:"
  write_to_file "$query_result"
fi




write_to_file "\n"
echo "5.4 Ensure 'SUPER' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.4 Ensure 'SUPER' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check SUPER privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SUPER';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'SUPER' privilege is not granted to non-administrative users."
else
  echwrite_to_fileo "FAIL: 'SUPER' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'SUPER' privilege:"
  write_to_file "$query_result"
fi





write_to_file "\n"
echo "5.5 Ensure 'SHUTDOWN' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.5 Ensure 'SHUTDOWN' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check SHUTDOWN privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SHUTDOWN';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'SHUTDOWN' privilege is not granted to non-administrative users."
else
  write_to_file "FAIL: 'SHUTDOWN' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'SHUTDOWN' privilege:"
  write_to_file "$query_result"
fi


write_to_file "\n"
echo "5.6 Ensure 'CREATE USER' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.6 Ensure 'CREATE USER' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check CREATE USER privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'CREATE USER';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'CREATE USER' privilege is not granted to non-administrative users."
else
  write_to_file "FAIL: 'CREATE USER' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'CREATE USER' privilege:"
  write_to_file "$query_result"
fi


write_to_file "\n"
echo "5.7 Ensure 'GRANT OPTION' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.7 Ensure 'GRANT OPTION' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check GRANT OPTION
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT DISTINCT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'GRANT OPTION' is not granted to non-administrative users."
else
  write_to_file "FAIL: 'GRANT OPTION' is granted to non-administrative users."
  write_to_file "Non-administrative users with 'GRANT OPTION':"
  write_to_file "$query_result"
fi

write_to_file "\n"
echo "5.8 Ensure 'REPLICATION SLAVE' is Not Granted to Non-Administrative Users (Manual)"
write_to_file  "5.8 Ensure 'REPLICATION SLAVE' is Not Granted to Non-Administrative Users (Manual)\n"
# Execute the SQL statement to check REPLICATION SLAVE privilege
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'REPLICATION SLAVE';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: 'REPLICATION SLAVE' privilege is not granted to non-administrative users."
else
  write_to_file "FAIL: 'REPLICATION SLAVE' privilege is granted to non-administrative users."
  write_to_file "Non-administrative users with 'REPLICATION SLAVE' privilege:"
  write_to_file "$query_result"
fi

write_to_file "\n"
echo "5.9 Ensure DML/DDL Grants are Limited to Specific Databases and Users (Manual)"
write_to_file  "5.9 Ensure DML/DDL Grants are Limited to Specific Databases and Users (Manual)\n"
# Execute the SQL statement to check DML/DDL grants
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT User, Host, Db FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y';")

# Check if any users have unrestricted DML/DDL privileges
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: DML/DDL grants are limited to specific databases and users."
else
  write_to_file "FAIL: DML/DDL grants are not limited to specific databases and users."
  write_to_file "Users with unrestricted DML/DDL privileges:"
  write_to_file "$query_result"
fi

write_to_file "\n"
echo "5.10 Securely Define Stored Procedures and Functions DEFINER and INVOKER (Manual)"
write_to_file  "5.10 Securely Define Stored Procedures and Functions DEFINER and INVOKER (Manual)\n"
echo "5.10 Escaped and should be performed manually."
write_to_file  "5.10 Escaped and should be performed manually.\n"



write_to_file "\n"
echo "6.1 Ensure 'log_error' is configured correctly (Automated)"
write_to_file  "6.1 Ensure 'log_error' is configured correctly (Automated)\n"
# Execute the SQL statement to get the value of 'log_error'
log_error=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW variables LIKE 'log_error';" | awk '{print $2}')

# Check if 'log_error' is configured correctly
if [[ "$log_error" != "./stderr.err" && "$log_error" != "" ]]; then
  write_to_file "PASS: 'log_error' is configured correctly."
else
  write_to_file "FAIL: 'log_error' is not configured correctly."
  write_to_file "Value of 'log_error': $log_error"
fi

write_to_file "\n"
echo "6.2 Ensure Log Files are Stored on a Non-System Partition (Automated)"
write_to_file  "6.2 Ensure Log Files are Stored on a Non-System Partition (Automated)\n"
# Execute the SQL statement to get the value of 'log_bin_basename'
log_bin_basename=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT @@global.log_bin_basename;" | awk '{print $2}')

# Check if log files are stored on a non-system partition
if [[ "$log_bin_basename" != *"/var/"* && "$log_bin_basename" != *"/usr/"* && "$log_bin_basename" != "/"* ]]; then
  write_to_file "PASS: Log files are stored on a non-system partition."
else
  write_to_file "FAIL: Log files are stored on a system partition."
  write_to_file "Value of 'log_bin_basename': $log_bin_basename"
fi


write_to_file "\n"
echo "6.3 Ensure 'log_warnings' is Set to '2' (Automated)"
write_to_file  "6.3 Ensure 'log_warnings' is Set to '2' (Automated)\n"
# Execute the SQL statement to get the value of 'log_warnings'
log_warnings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW GLOBAL VARIABLES LIKE 'log_warnings';" | awk '{print $2}')

# Check if 'log_warnings' is set to '2'
if [[ "$log_warnings" == "2" ]]; then
  write_to_file "PASS: 'log_warnings' is set to '2'."
else
  write_to_file "FAIL: 'log_warnings' is not set to '2'."
  ecwrite_to_fileho "Value of 'log_warnings': $log_warnings"
fi


write_to_file "\n"
echo "6.4 Ensure Audit Logging Is Enabled (Automated)"
write_to_file  "6.4 Ensure Audit Logging Is Enabled (Automated)\n"
# Execute the SQL statement to check audit-related variables
audit_logging=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE '%audit%';")

# Check if the audit logging variables are configured properly
if [[ $audit_logging =~ "audit_log_format" && $audit_logging =~ "audit_log_policy" && $audit_logging =~ "audit_log_rotate_on_size" ]]; then
  write_to_file "PASS: Audit logging is enabled and properly configured."
else
  write_to_file "FAIL: Audit logging is not enabled or not properly configured."
  write_to_file "Audit logging variables:"
  write_to_file "$audit_logging"
fi

write_to_file "\n"
echo "6.5 Ensure the Audit Plugin Can't be Unloaded (Automated)"
write_to_file  "6.5 Ensure the Audit Plugin Can't be Unloaded (Automated)\n"
# Execute the SQL statement to check the audit plugin load option
load_option=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME='SERVER_AUDIT';")

# Check if the load option is set to FORCE_PLUS_PERMANENT
if [[ $load_option == "FORCE_PLUS_PERMANENT" ]]; then
  write_to_file "PASS: Audit plugin cannot be unloaded."
else
  write_to_file "FAIL: Audit plugin can be unloaded."
  write_to_file "Audit plugin load option: $load_option"
fi

write_to_file "\n"
echo "6.6 Ensure Binary and Relay Logs are Encrypted (Automated)"
write_to_file  "6.6 Ensure Binary and Relay Logs are Encrypted (Automated)\n"
# Execute the SQL statement to check the encryption settings for binary and relay logs
encryption_settings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - At Rest Encryption' as Note FROM information_schema.global_variables WHERE variable_name LIKE '%ENCRYPT_LOG%';")

# Check if the encryption setting is ON
if [[ $encryption_settings == *"ON"* ]]; then
  write_to_file "PASS: Binary and relay logs are encrypted."
else
  write_to_file "FAIL: Binary and relay logs are not encrypted."
  write_to_file "Encryption settings:"
  write_to_file "$encryption_settings"
fi

write_to_file "\n"
echo "7.1 Disable use of the mysql_old_password plugin (Automated)"
write_to_file  "7.1 Disable use of the mysql_old_password plugin (Automated)\n"
# Check if the mysql_old_password plugin is disabled for new passwords
password_setting=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES WHERE Variable_name = 'old_passwords';")

# Extract the value from the result
password_value=$(echo "$password_setting" | awk 'NR==2 {print $2}')

# Check if the value is set to OFF
if [[ $password_value == "OFF" ]]; then
  write_to_file "PASS: mysql_old_password plugin is disabled for new passwords."
else
  write_to_file "FAIL: mysql_old_password plugin is not disabled for new passwords."
  write_to_file"Password setting:"
  write_to_file "$password_setting"
fi

# Check if connections using mysql_old_password plugin are blocked
plugin_setting=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'secure_auth';")

# Extract the value from the result
plugin_value=$(echo "$plugin_setting" | awk 'NR==2 {print $2}')

# Check if the value is set to YES
if [[ $plugin_value == "YES" ]]; then
  write_to_file "PASS: Connections using mysql_old_password plugin are blocked."
else
  write_to_file "FAIL: Connections using mysql_old_password plugin are not blocked."
  ecwrite_to_fileho "Plugin setting:"
  write_to_file "$plugin_setting"
fi

write_to_file "\n"
echo "7.2 Ensure Passwords are Not Stored in the Global Configuration (Automated)"
write_to_file  "7.2 Ensure Passwords are Not Stored in the Global Configuration (Automated)\n"
write_to_file "Escaped"
write_to_file "NOTICE: To assess this recommendation, perform the following steps:
1. Open the MariaDB configuration file (e.g., mariadb.cnf)
2. Examine the [client] section of the MariaDB configuration file and ensure password is not employed."

write_to_file "\n"
echo "7.3 Ensure strong authentication is utilized for all accounts (Automated)"
write_to_file  "7.3 Ensure strong authentication is utilized for all accounts (Automated)\n"
# Execute the SQL query to find users utilizing specific plugins
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT User, host FROM mysql.user WHERE (plugin IN ('mysql_native_password', 'mysql_old_password', '') AND NOT authentication_string = 'invalid');")

# Check if any rows are returned
if [[ -z "$query_result" ]]; then
  write_to_file "PASS: Strong authentication is utilized for all accounts."
else
  write_to_file "FAIL: Some accounts are not using strong authentication mechanisms."
  write_to_file "Affected accounts:"
  write_to_file "$query_result"
fi

write_to_file "\n"
echo "7.4 Ensure Password Complexity Policies are in Place (Automated)"
write_to_file  "7.4 Ensure Password Complexity Policies are in Place (Automated)\n"
# Check if plugin_load_add entries exist in the configuration file
if grep -q "plugin_load_add = simple_password_check" "$config_file" && grep -q "plugin_load_add = cracklib_password_check" "$config_file"; then
  write_to_file "PASS: Password complexity plugins are configured in the MariaDB configuration file."
else
  write_to_file "FAIL: Password complexity plugins are not configured in the MariaDB configuration file."
fi

# Check if simple_password_check and cracklib_password_check plugins are active
plugin_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" --defaults-extra-file="$config_file" -e "SHOW PLUGINS;")

if [[ $plugin_status == *"simple_password_check"*"ACTIVE"* ]] && [[ $plugin_status == *"cracklib_password_check"*"ACTIVE"* ]]; then
  write_to_file "PASS: Password complexity plugins (simple_password_check and cracklib_password_check) are active."
else
  write_to_file "FAIL: Password complexity plugins (simple_password_check and cracklib_password_check) are not active."
fi

# Check password policy settings
password_settings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" --defaults-extra-file="$config_file" -e "SHOW VARIABLES LIKE '%pass%';")

minimal_length=$(echo "$password_settings" | awk '/simple_password_check_minimal_length/ {print $2}')
strict_validation=$(echo "$password_settings" | awk '/strict_password_validation/ {print $2}')
cracklib_dictionary=$(echo "$password_settings" | awk '/cracklib_password_check_dictionary/ {print $2}')

if [[ $minimal_length -ge 14 ]] && [[ $strict_validation == "ON" ]] && [[ $cracklib_dictionary != "" ]]; then
  write_to_file "PASS: Password policy settings are in place."
else
  write_to_file "FAIL: Password policy settings are not configured correctly."
  write_to_file "Password policy settings:"
  write_to_file "$password_settings"
fi


write_to_file "\n"
echo "7.5 Ensure No Users Have Wildcard Hostnames (Automated)"
write_to_file  "7.5 Ensure No Users Have Wildcard Hostnames (Automated)\n"
# Execute SQL statement to check for wildcard hostnames
wildcard_users=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT user, host FROM mysql.user WHERE host = '%';" | tail -n +2)

# Check if any rows are returned
if [ -z "$wildcard_users" ]; then
  write_to_file "PASS: No users with wildcard hostnames found."
else
  write_to_file "FAIL: Users with wildcard hostnames found:"
  write_to_file "$wildcard_users"
fi

write_to_file "\n"
echo "7.6 Ensure No Anonymous Accounts Exist (Automated)"
write_to_file  "7.6 Ensure No Anonymous Accounts Exist (Automated)\n"
# Execute SQL query to check for anonymous accounts
anonymous_accounts=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT user, host FROM mysql.user WHERE user = '';" | tail -n +2)

# Check if any rows are returned
if [ -z "$anonymous_accounts" ]; then
  write_to_file "PASS: No anonymous accounts found."
else
  write_to_file "FAIL: Anonymous accounts found:"
  write_to_file "$anonymous_accounts"
fi




# End of script
write_to_file "\nAudit completed."

echo "Audit completed. Results are stored in $output_file."
done
