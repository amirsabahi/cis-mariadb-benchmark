#!/bin/bash  

# MariaDB CIS Benchmark Audit Script

# Output file
output_file="maridb_audit_results.txt"

# Function to write audit results to the output file
write_to_file() {
    echo -e "$1" >> "$output_file"
}

#!/bin/bash

function log_message() {
  message=$1
  type=${2:-message}  # Default type is "message"
  log_file="log.txt"

  # Define color codes
  message_color="\033[0m"
  red_color="\033[0;31m"
  yellow_color="\033[0;33m"
  blue_color="\033[0;34m"
  green_color="\033[0;32m"

  # Determine color based on the type
  if [[ "$type" == "error" ]]; then
    color=$red_color
  elif [[ "$type" == "notice" ]]; then
    color=$yellow_color
  elif [[ "$type" == "info" ]]; then
    color=$blue_color
 elif [[ "$type" == "success" ]]; then
    color=$green_color   
  else
    color=$message_color
  fi

  # Echo message with color
  echo -e "${color}${message}${message_color}"

  # Write message to log file
  write_to_file "$(date +"%Y-%m-%d %H:%M:%S") - [$type] - $message"
}


# Check if the output file exists and delete it
if [ -f "$output_file" ]; then
    rm "$output_file"
fi

# Audit MariaDB configuration
log_message "==========================="
log_message "MariaDB CIS Benchmark Audit (1.60)"
log_message "===========================\n"


read -p "Enter the path to the MariaDB configuration file (e.g., /etc/mysql/my.cnf): " config_file

# Prompt for mariadbd startup command path
read -p "Enter the path to the mariadbd startup command: ( /usr/bin/mysql or /etc/bin/mysql): " mariadb_startup_command

# Prompt the user for MariaDB credentials
read -p "Enter MariaDB Username: " username
read -s -p "Enter MariaDB Password: " password
echo
read -p "Enter MariaDB Host (default: 127.0.0.1): " host
host=${host:-127.0.0.1}
read -p "Enter MariaDB Port (default: 3306): " port
port=${port:-3306}

log_message "1.1 Operating System Level Configuration"

# Obtain the location of MariaDB database files
sql_query="SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM information_schema.global_variables
WHERE (VARIABLE_NAME LIKE '%dir' OR VARIABLE_NAME LIKE '%file') AND
(VARIABLE_NAME NOT LIKE '%core%' AND VARIABLE_NAME <> 'local_infile' AND VARIABLE_NAME <> 'relay_log_info_file')
ORDER BY VARIABLE_NAME;"

datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "$sql_query" | grep 'DATADIR' | awk '{print $2}')

# Check if datadir result is empty
if [ -z "$datadir_result" ]; then
  log_message "Failed to obtain datadir location." "error"

fi

# Execute df command for datadir location
df_output=$(df -h "$datadir_result" | grep -vE "^Filesystem|/var|/usr|/$")

# Display the df output
if [ -nz "$df_output" ]; then
echo "$df_output"
  echo "Failed to obtain datadir location." "error"
  log_message "The output returned from the df command above should not include root (/), /var, or /usr."
else
   log_message "PASS: 1.1 Place Databases on Non-System Partitions (Manual)" "success"
fi


log_message  "1.2 Use Dedicated Least Privileged Account for MariaDB Daemon/Service (Automated)"
# Execute the command to assess the recommendation
output=$(ps -ef | egrep "^mysql.*$")

# Check if any lines are returned
if [ -z "$output" ]; then
  log_message "FAIL: No MySQL/MariaDB process found." "error"
else
  log_message "PASS: MySQL/MariaDB process is running." "success"
fi

# Check sudo privileges for the MariaDB user
sudo_output=$(sudo -l -U mysql 2>/dev/null)

# Check if sudo privileges exist
if [ -n "$sudo_output" ]; then
  log_message "FAIL: Sudo Privileges: Sudo privileges are available for the MariaDB user." "error"
else
  log_message "PASS: Sudo Privileges: No sudo privileges found for the MariaDB user." "success"
fi

log_message  "1.3 Disable MariaDB Command History (Automated)"

# Find .mysql_history files in /home directory
home_files=$(find /home -name ".mysql_history")

# Find .mysql_history files in /root directory
root_files=$(find /root -name ".mysql_history")

# Combine the file lists
all_files="$home_files"$'\n'"$root_files"

# Check if any .mysql_history files are found
if [ -z "$all_files" ]; then
  log_message "NOTICE: No .mysql_history files found." "info"

fi

# Iterate over each file and check if it is symbolically linked to /dev/null
for file in $all_files; do
  if [ -L "$file" ] && [ "$(readlink "$file")" == "/dev/null" ]; then
    log_message "PASS: File: $file is symbolically linked to /dev/null" "success"
  else
    log_message "FAIL: File: $file is not symbolically linked to /dev/null" "error"
  fi


log_message "1.4 Verify That the MYSQL_PWD Environment Variable is Not in Use (Automated)"
# Verify That the MYSQL_PWD Environment Variable is Not in Use
output=$(grep MYSQL_PWD /proc/*/environ | grep -vE "^/proc/$$")

# Check if any entries are returned
if [ -z "$output" ]; then
  log_message "PASS: MYSQL_PWD is not set for any process." "success"
else
  log_message "FAIL: MYSQL_PWD is set for the following process(es):" "error"
  log_message "$output"
fi

log_message  "1.5 Ensure Interactive Login is Disabled (Automated)"
# Execute the command to assess the recommendation
output=$(getent passwd mysql | egrep "^.*[\/bin\/false|\/sbin\/nologin]$")
# Check if any output is returned
if [ -z "$output" ]; then
  log_message "FAIL: Interactive login is not disabled for the mysql user." "error"
else
  log_message "PASS: Interactive login is disabled for the mysql user." "success"
fi

log_message  "1.6 Verify That 'MYSQL_PWD' is Not Set in Users' Profiles(Automated)"
# Execute the command to verify MYSQL_PWD in users' profiles
output=$(grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 2>/dev/null)

# Check if any lines are returned
if [ -z "$output" ]; then
  log_message "PASS: MYSQL_PWD is not set in users' profiles." "success"
else
  log_message "FAIL: MYSQL_PWD is set in the following user profiles:" "error"
  log_message "$output"
fi

log_message  "1.7 Ensure MariaDB is Run Under a Sandbox Environment(Manual)"
# Step 1: Check chroot
chroot_path=$(cat /etc/mysql/my.cnf | egrep -o '(?<=^chroot=).+$')

if [ -z "$chroot_path" ]; then
  log_message "FAIL: 'chroot' is not in use." "error"
else
  log_message "PASS: 'chroot' is set to $chroot_path." "success"
fi

# Step 2: Check systemd
systemd_status=$(systemctl status mariadb.service)

if echo "$systemd_status" | grep -q "(root)"; then
  log_message "PASS: MariaDB is managed by systemd." "success"
else
  log_message "FAIL: MariaDB is not managed by systemd." "error"
fi

systemd_status=$(systemctl status mysql.service)
if echo "$systemd_status" | grep -q "(root)"; then
  log_message "PASS: MySQL(MariaDB) is managed by systemd." "success"
else
  log_message "FAIL: MySQL(MariaDB) is not managed by systemd." "error"
fi

#
# Step 3: Check Docker
docker_version=$(docker -v 2>&1)

if echo "$docker_version" | grep -q "Docker version"; then
  log_message "PASS: Docker is installed." "success"

  # Check MariaDB image in Docker
  mariadb_image=$(sudo docker images -q mariadb:latest)

  if [ -z "$mariadb_image" ]; then
    log_message "FAIL: MariaDB image is not found in Docker." "error"
  else
    log_message "PASS: MariaDB image exists in Docker." "success"

    # Check MariaDB container in Docker
    mariadb_container=$(sudo docker ps -q -f ancestor=mariadb:latest)

    if [ -z "$mariadb_container" ]; then
      log_message "FAIL: MariaDB container is not running in Docker." "error"
    else
      log_message "PASS: MariaDB container is running in Docker." "success"
    fi
  fi
else
  log_message "FAIL: Docker is not installed." "error"
fi

log_message "Escaped audits 2.1.1, 2.1.2, 2.1.3, 2.1.4, 2.1.5, 2.1.6, 2.1.7, 2.2, 2.3, 2.5, 2.8" "warning"

log_message "Do you have a solid backup plan? This script do not check all the 2.1 Backup and Disaster Recovery. Use following link to learn more: https://mariadb.com/kb/en/using-encryption-and-compression-tools-with-mariabackup/" "info"

log_message  "2.1.5 Point-in-Time Recovery (Automated)"
# Check if binlogs are enabled
binlog_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'log_bin';" | awk 'NR>1 {print $2}')

if [ "$binlog_status" = "ON" ]; then
  log_message "PASS: Binlogs are enabled." "success"
else
  log_message "FAIL: Binlogs are not enabled." "error"
fi

# Check if there is a restore procedure
restore_procedure=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW PROCEDURE STATUS WHERE Name = 'restore_backup';" | awk 'NR>1')

if [ -n "$restore_procedure" ]; then
  log_message "PASS: Restore procedure 'restore_backup' exists." "success"
else
  log_message "FAIL: Restore procedure 'restore_backup' does not exist." "error" "error"
fi

# Check if binlog_expire_logs_seconds is set
expire_logs_seconds=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'binlog_expire_logs_seconds';" | awk 'NR>1')

if [ "$expire_logs_seconds" != "0" ]; then
  log_message "PASS: binlog_expire_logs_seconds is set to $expire_logs_seconds." "success"
else
  log_message "FAIL: binlog_expire_logs_seconds is set to 0." "error"
fi

log_message "2.4 Do Not Reuse Usernames (Manual)"

sql_query="SELECT host, user, plugin,
IF(plugin = 'mysql_native_password',
'WEAK SHA1', 'STRONG SHA2') AS HASHTYPE
FROM mysql.user WHERE user NOT IN
('mysql.infoschema', 'mysql.session', 'mysql.sys') AND
plugin NOT LIKE 'auth%' AND plugin <> 'mysql_no_login' AND
LENGTH(authentication_string) > 0
ORDER BY plugin;"

log_message "Each user (excluding mysql reserved users) should be linked to one of these:
• system accounts
• a person
• an application"
datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "$sql_query")
log_message $datadir_result

log_message  "2.6 Ensure 'password_lifetime' is Less Than or Equal to '365'(Automated)"
# Check global password lifetime
global_lifetime=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'default_password_lifetime';")

if [ $global_lifetime -gt 365 ]; then
  log_message "FAIL: Global password lifetime is greater than 365." "error"
else
  log_message "PASS: Global password lifetime is less than or equal to 365, or not configured." "success"
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
log_message "User Password Expiration:"

if [ -n "$user_password_expiration" ]; then
  log_message "$user_password_expiration"
else
  log_message "No user accounts found."
fi

log_message  "2.7 Lock Out Accounts if Not Currently in Use (Manual)"
# Check account lock status
lock_status_query="SELECT CONCAT(user, '@', host, ' => ', JSON_DETAILED(priv)) FROM mysql.global_priv;"

account_lock_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$lock_status_query")

# Write account lock status to the file
log_message "Accounts not in use and MariaDB Reserved accounts should show as account_locked:true "
log_message "Account Lock Status:"

if [ -n "$account_lock_status" ]; then
  log_message "$account_lock_status"
else
  log_message "No accounts found."
fi

log_message  "2.8 Ensure Socket Peer-Credential Authentication is Used Appropriately (Manual)"

# Check if unix_socket plugin is enabled
plugin_status_query="SELECT PLUGIN_NAME, PLUGIN_STATUS FROM INFORMATION_SCHEMA.PLUGINS WHERE PLUGIN_NAME = 'unix_socket';"

plugin_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$plugin_status_query")

# Write plugin status to the file
log_message "If PLUGIN_STATUS is ACTIVE and the organization does not allow use of this feature, this is a fail." "info"
log_message "Plugin Status:"

if [ -n "$plugin_status" ]; then
  log_message "$plugin_status"
else
  log_message "Plugin not found."
fi

# Check users who can use unix_socket
user_unix_socket_query="SELECT CONCAT(user, '@', host, ' => ', JSON_DETAILED(priv)) FROM mysql.global_priv WHERE JSON_CONTAINS(priv, '{"plugin":"unix_socket"}', '$.auth_or');"

user_unix_socket=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$user_unix_socket_query")

# Write users who can use unix_socket to the file
log_message "If host is not the localhost or an unauthorized user is listed, this is a fail." "info"
log_message "Users with unix_socket privilege:"

if [ -n "$user_unix_socket" ]; then
  log_message "$user_unix_socket"
else
  log_message "No users found."
fi

log_message  "2.9 Ensure MariaDB is Bound to an IP Address (Automated)"
# Run SQL statement to check bind_address variable
bind_address_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'bind_address';"

bind_address_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$bind_address_query")

# Write results to the file
log_message "Any empty VARIABLE_VALUE implies a fail." "info"
log_message "Bind Address Audit:"

if [ -n "$bind_address_result" ]; then
  log_message "$bind_address_result"
else
  log_message "No results found."
fi

log_message  "2.10 Limit Accepted Transport Layer Security (TLS) Versions (Automated)"
# Check TLS versions
tls_versions_query="select @@tls_version;"

tls_versions_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$tls_versions_query")

# Write results to the file
log_message "If the list includes TLSv1 and/or TLSv1.1, this is a fail."
log_message "TLS Version Audit:"

if [[ "$tls_versions_result" == *"TLSv1.0"* ]]; then
  log_message "FAIL: TLSv1.0 is present" "error"
elif [[ "$tls_versions_result" == *"TLSv1.1"* ]]; then
  log_message "FAIL: TLSv1.1 is present" "error"
else
  log_message "PASS: No TLSv1.0 or 1.1" "success"
fi

log_message  "2.11 Require Client-Side Certificates (X.509) (Automated)"

# Check SSL type for users
ssl_type_query="SELECT user, host, ssl_type FROM mysql.user WHERE user NOT IN ('mysql', 'root', 'mariadb.sys');"

ssl_type_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$ssl_type_query")

# Write results to the file
"If ssl_type returns X509, client-side certificate details must be provided to connect."
log_message log_message "Client-Side Certificate Audit:"

if [ -n "$ssl_type_result" ]; then
  log_message "$ssl_type_result"
else
  log_message "No results found."
fi

log_message  "2.12 Require Client-Side Certificates (X.509) (Automated)"

# Run the SQL statement to check SSL ciphers
ssl_ciphers_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME = 'ssl_cipher';"

ssl_ciphers_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$ssl_ciphers_query" | awk '{print $2}')

# Write results to the file
log_message "SSL Ciphers Audit:"

if [ -n "$ssl_ciphers_result" ]]; then
  log_message "PASS: $ssl_ciphers_result" "success"
else
  log_message "FAIL: No results found." "error"
fi

# Check if SSL ciphers are empty or contain unapproved ciphers
approved_ciphers=("ECDHE","ECDSA", "AES128", "GCM", "SHA256")  # Add your approved ciphers here

IFS=$''
for cipher in $ssl_ciphers_result; do
  cipher_name=$(echo "$cipher" | awk '{print $2}')
  if [ -z "$cipher_name" ]]; then
    log_message "FAIL: SSL ciphers are empty." "error"
  elif [ ! " ${approved_ciphers[@]} " =~ " $cipher_name " ]]; then
    log_message "FAIL: Unapproved cipher found: $cipher_name" "error"
  else
    log_message "PASS: $cipher_name" "success"
  fi
done

# Reset IFS
unset IFS

log_message  "3.1 Ensure 'datadir' Has Appropriate Permissions (Automated)"

# Execute the SQL statement to determine the value of datadir
datadir_query="SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME LIKE 'DATADIR';"

datadir_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$datadir_query")

# Write results to the file
log_message "datadir Permissions Audit:"

if [[ -n "$datadir_result" ]]; then
  log_message "$datadir_result"
  
  # Extract the datadir path from the result
  datadir_path=$(echo "$datadir_result" | awk 'NR>1 {print $2}')
  
  # Execute the command to check datadir permissions
  permissions_check=$(sudo ls -ld "$datadir_path" | grep "drwxr-x---.*mysql.*mysql")
  
  if [[ -z "$permissions_check" ]]; then
    log_message "FAIL: 'datadir' does not have appropriate permissions." "error"
  else
    log_message "PASS: 'datadir' has appropriate permissions." "success"
  fi
else
  log_message "No 'datadir' value found."
  log_message "FAIL: Unable to determine 'datadir' path." "error"
fi

log_message  "3.2 Ensure 'log_bin_basename' Files Have AppropriatePermissions (Automated)"

# Execute the SQL statement to determine the value of log_bin_basename
log_bin_basename_query="show variables like 'log_bin_basename';"

log_bin_basename_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$log_bin_basename_query")

# Write results to the file
log_message "log_bin_basename Permissions Audit:"

if [[ -n "$log_bin_basename_result" ]]; then
  log_message "$log_bin_basename_result"
  
  # Extract the log_bin_basename value from the result
  log_bin_basename=$(echo "$log_bin_basename_result" | awk 'NR>1 {print $2}')
  
  # Execute the command to check log_bin_basename file permissions
  permissions_check=$(ls -l | egrep '^-(?![r|w]{2}-[r|w]{2}----.*mysql\s*mysql).*'"$log_bin_basename"'.*$')
  
  if [[ -z "$permissions_check" ]]; then
    log_message "PASS: 'log_bin_basename' files have appropriate permissions." "success"
  else
    log_message "FAIL: Non-compliant 'log_bin_basename' file permissions found:" "error"
    log_message "$permissions_check"
  fi
else
  log_message "No 'log_bin_basename' value found."
  log_message "FAIL: Unable to determine 'log_bin_basename'." "error"
fi

log_message  "3.3 Ensure 'log_error' Has Appropriate Permissions (Automated)"

# Execute the SQL statement to determine the value of log_error
log_error_query="show variables like 'log_error';"

log_error_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$log_error_query")

# Write results to the file
log_message "log_error Permissions Audit:"

if [[ -n "$log_error_result" ]]; then
  log_message "$log_error_result"
  
  # Extract the log_error value from the result
  log_error=$(echo "$log_error_result" | awk 'NR>1 {print $2}')
  
  # Execute the command to check log_error file permissions
  permissions_check=$(ls -l "$log_error" | grep '^-rw-------.*mysql.*mysql.*$')
  
  if [[ -z "$permissions_check" ]]; then
    log_message "PASS: 'log_error' file has appropriate permissions." "success"
  else
    log_message "FAIL: Non-compliant 'log_error' file permissions found:" "error"
    log_message "$permissions_check"
  fi
else
  log_message "No 'log_error' value found."
  log_message "FAIL: Unable to determine 'log_error'." "error"
fi

log_message  "3.4 Ensure 'slow_query_log' Has Appropriate Permissions (Automated)"

# Execute the SQL statement to determine the value of slow_query_log
slow_query_log_query="show variables like 'slow_query_log';"

slow_query_log_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$slow_query_log_query")

# Write results to the file
log_message "slow_query_log Permissions Audit:"

if [[ -n "$slow_query_log_result" ]]; then
  log_message "$slow_query_log_result"
  
  # Extract the slow_query_log value from the result
  slow_query_log=$(echo "$slow_query_log_result" | awk 'NR>1 {print $2}')
  
  # Check if slow_query_log is enabled or disabled
  if [[ "$slow_query_log" == "OFF" ]]; then
    log_message "Slow query log is disabled."
    
    # Remove any old slow query log files
    rm -f "$slow_query_log"
    
    log_message "Old slow query log files removed."
  else
    # Execute the SQL statement to determine the location of slow_query_log_file
    slow_query_log_file_query="show variables like 'slow_query_log_file';"

    slow_query_log_file_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$slow_query_log_file_query")

    if [[ -n "$slow_query_log_file_result" ]]; then
      log_message "$slow_query_log_file_result"
      
      # Extract the slow_query_log_file value from the result
      slow_query_log_file=$(echo "$slow_query_log_file_result" | awk '{print $2}')
      
      # Execute the command to check slow_query_log_file permissions
      permissions_check=$(ls -l "/var/log/mysql/$slow_query_log_file" | grep '^-rw-------.*mysql.*mysql.*$')
      
      if [[ -z "$permissions_check" ]]; then
        log_message "FAIL: Non-compliant 'slow_query_log_file' permissions found:" "error"
        log_message "$permissions_check"
      else
        log_message "PASS: 'slow_query_log_file' has appropriate permissions." "success"
      fi
    else
      log_message "No 'slow_query_log_file' value found."
      log_message "FAIL: Unable to determine 'slow_query_log_file'." "error"
    fi
  fi
else
  log_message "No 'slow_query_log' value found."
  log_message "FAIL: Unable to determine 'slow_query_log'." "error"
fi

log_message  "3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions (Automated)"

# Execute the SQL statement to determine the value of relay_log_basename
relay_log_basename_query="show variables like 'relay_log_basename';"

relay_log_basename_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -B -N -e "$relay_log_basename_query")

# Write results to the file
log_message "relay_log_basename Permissions Audit:"

if [[ -n "$relay_log_basename_result" ]]; then
  log_message "$relay_log_basename_result"
  
  # Extract the relay_log_basename value from the result
  relay_log_basename=$(echo "$relay_log_basename_result" | awk 'NR>1 {print $2}')
  
  # Execute the command to check relay_log_basename file permissions
  permissions_check=$(ls -l | egrep "^-(?![r|w]{2}-[r|w]{2}----.*mysql\s*mysql).*${relay_log_basename}.*$")

  if [[ -z "$permissions_check" ]]; then
    log_message "PASS: 'relay_log_basename' files have appropriate permissions." "success"
  else
    log_message "FAIL: Non-compliant 'relay_log_basename' file permissions found:" "error"
    log_message "$permissions_check"
  fi
else
  log_message "No 'relay_log_basename' value found."
  log_message "FAIL: Unable to determine 'relay_log_basename'." "error"
fi

log_message  "3.6 Ensure 'general_log_file' Has Appropriate Permissions (Automated)"

# Execute the SQL statement to determine the values of general_log and general_log_file
general_log_query="select @@general_log, @@general_log_file;"

general_log_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -B -N -e "$general_log_query")

# Write results to the file
log_message "general_log_file Permissions Audit:"

if [[ -n "$general_log_result" ]]; then
  log_message "$general_log_result"
  
  # Extract the general_log and general_log_file values from the result
  general_log=$(echo "$general_log_result" | awk '{print $1}')
  general_log_file=$(echo "$general_log_result" | awk '{print $2}')
  
  # Check if the general log is enabled or disabled
  if [[ "$general_log" == "0" || "$general_log" == "OFF" ]]; then
    if [[ -f "$general_log_file" ]]; then
      # General log is disabled, remove the old general log file
      rm "$general_log_file"
      log_message "General log file removed."
    else
      log_message "General log is disabled. No log file found."
    fi
  elif [[ "$general_log" == "1" || "$general_log" == "ON" ]]; then
    # General log is enabled, check the file permissions
    permissions_check=$(ls -l "$general_log_file" | grep '^-rw-------.*mysql.*mysql')
  
    if [[ -z "$permissions_check" ]]; then
      log_message "FAIL: Non-compliant 'general_log_file' permissions found:" "error"
      log_message "$permissions_check"
    else
      log_message "PASS: 'general_log_file' has appropriate permissions." "success"
    fi
  else
    log_message "Unknown general_log value: $general_log"
    log_message "Unable to assess 'general_log_file' permissions."
  fi
else
  log_message "No 'general_log' or 'general_log_file' values found."
  log_message "FAIL: Unable to determine 'general_log' and 'general_log_file'." "error"
fi

log_message  "3.7 Ensure SSL Key Files Have Appropriate Permissions (Automated)"

# Execute the SQL statement to retrieve SSL key files
ssl_key_files=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE REGEXP_INSTR(VARIABLE_NAME, '^.*ssl_(ca|capath|cert|crl|crlpath|key)$') AND VARIABLE_VALUE <> '';" | tail -n +2)

# Perform the permissions audit for each SSL key file
log_message "SSL Key Files Permissions Audit:"

while IFS= read -r ssl_file; do
  # Check if the SSL key file exists
  if [[ -f "$ssl_file" ]]; then
    permissions_check=$(ls -l "$ssl_file" | egrep '^-.(?!r-{8}.*mysql\s*mysql).*$')
  
    if [[ -z "$permissions_check" ]]; then
      log_message "PASS: SSL key file has appropriate permissions: $ssl_file" "success"
    else
      log_message "FAIL: Non-compliant permissions found for SSL key file: $ssl_file" "error"
      log_message "$permissions_check"
    fi
  else
    log_message "SSL key file does not exist: $ssl_file"
  fi
done <<< "$ssl_key_files"

log_message  "3.8 Ensure Plugin Directory Has Appropriate Permissions (Automated)"

# Retrieve plugin directory value from MySQL
plugin_dir=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "show variables where variable_name = 'plugin_dir'" | awk '/plugin_dir/ {print $2}')

# Check permissions and ownership of the plugin directory
ls -ld "$plugin_dir" | grep -E "dr-xr-x---|dr-xr-xr--" | grep "plugin"

# Check if there was any output from the command
if [ $? -eq 0 ]; then
  log_message "PASS: Plugin directory has appropriate permissions." "success"
else
  log_message "FAIL: Plugin directory does not have appropriate permissions." "error"
fi

log_message  "3.9 Ensure 'server_audit_file_path' Has Appropriate Permissions (Automated)"

# Retrieve 'server_audit_file_path' value from MySQL
server_audit_file_path=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "show global variables where variable_name='server_audit_file_path'" | awk '/server_audit_file_path/ {print $2}')

# Check if 'server_audit_file_path' value is empty
if [[ -z "$server_audit_file_path" ]]; then
  log_message "FAIL: Auditing is not installed." "error"
fi

# Check permissions and ownership of the server audit file path
ls -l "$server_audit_file_path" | grep -E "^-([rw-]{2}-){2}---[ \t]*[0-9][ \t]*mysql[ \t]*mysql.*$"

# Check if there was any output from the command
if [ $? -eq 0 ]; then
  log_message "PASS: 'server_audit_file_path' has appropriate permissions." "success"
else
  log_message "FAIL: 'server_audit_file_path' does not have appropriate permissions." "error"
fi

log_message  "3.10 Ensure File Key Management Encryption Plugin files have appropriate permissions (Automated)"
# Step 1: Find the file_key_management_filename value
file_key_management_filename=$(grep -Po '(?<=file_key_management_filename=).+$' /etc/mysql/mariadb.cnf)

# Check if file_key_management_filename value is empty
if [[ -z "$file_key_management_filename" ]]; then
  log_message "FAIL: File Key Management Encryption plugin is not configured." "error"
fi

# Verify permissions for file_key_management_filename
file_key_management_filename_permissions=$(stat -c "%a %U:%G" "$file_key_management_filename")

# Check if permissions are 750 or more restrictive for file_key_management_filename
if [[ "$file_key_management_filename_permissions" =~ ^(750|[0-6]{2}[0-7]{1}[0-7]{1})\ mysql:mysql$ ]]; then
  log_message "PASS: 'file_key_management_filename' has appropriate permissions." "success"
else
  log_message "FAIL: 'file_key_management_filename' does not have appropriate permissions." "error"
fi

# Step 2: Find the file_key_management_filekey value
file_key_management_filekey=$(grep -Po '(?<=file_key_management_filekey=).+$' /etc/mysql/mariadb.cnf)

# Verify permissions for file_key_management_filekey
file_key_management_filekey_permissions=$(stat -c "%a %U:%G" "$file_key_management_filekey")

# Check if permissions are 750 or more restrictive for file_key_management_filekey
if [[ "$file_key_management_filekey_permissions" =~ ^(750|[0-6]{2}[0-7]{1}[0-7]{1})\ mysql:mysql$ ]]; then
  log_message "PASS: 'file_key_management_filekey' has appropriate permissions." "success"
else
  log_message "FAIL: 'file_key_management_filekey' does not have appropriate permissions." "error"
fi

log_message  "4.1 Ensure the Latest Security Patches are Applied (Manual)"

# Execute SQL statement to identify MariaDB server version
mariadb_version=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -N -B -e "SHOW VARIABLES WHERE Variable_name LIKE 'version';" | awk 'NR>1 {print $2}')

# Compare the version with security announcements
latest_version="11.2"  # Update this with the latest version announced

if [[ "$mariadb_version" == "$latest_version" ]]; then
  log_message "PASS: MariaDB server is up to date." "success"
else
  log_message "FAIL: MariaDB server may not have the latest security patches applied. Current installed version is: $mariadb_version" "error"
fi

log_message  "4.2 Ensure Example or Test Databases are Not Installed on Production Servers (Automated)"

# Execute SQL statement to determine if test database is present
result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -N -B -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('mysql', 'information_schema', 'sys', 'performance_schema');")

if [[ $result -gt 0 ]]; then
  log_message "FAIL: Test or example databases are present on the server." "error"
else
  log_message "PASS: No test or example databases found." "success"
fi

log_message  "4.3 Ensure 'allow-suspicious-udfs' is Set to 'OFF' (Automated)"

# Check mariadbd startup command line for --allow-suspicious-udfs
if grep -q -- '--allow-suspicious-udfs' "$mariadb_startup_command"; then
  log_message "FAIL: 'allow-suspicious-udfs' is specified in the mariadbd startup command line." "error"
else
  log_message "PASS: 'allow-suspicious-udfs' is not specified in the mariadbd startup command line." "success"
fi

# Check MariaDB configuration for 'allow-suspicious-udfs'
result=$(my_print_defaults mysqld | grep -c 'allow-suspicious-udfs')

if [[ $result -eq 0 ]]; then
  log_message "PASS: 'allow-suspicious-udfs' is set to 'OFF' in the MariaDB configuration." "success"
else
  log_message "FAIL: 'allow-suspicious-udfs' is not set to 'OFF' in the MariaDB configuration." "error"
fi

log_message "4.4 Harden Usage for 'local_infile' on MariaDB Clients (Automated)"
# Check MariaDB client version
client_version=$(mariadb --version | awk '{print $5}')
required_version="10.2.0"
log_message "NOTICE: MariaDB client version should be $required_version or higher. Current version is: $client_version" "info"

# Check local_infile variable
local_infile_value=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -e "SHOW VARIABLES WHERE Variable_name = 'local_infile'" | grep local_infile | awk 'NR>1 {print $2}')

if [[ $local_infile_value == "OFF" || $local_infile_value == "0" ]]; then
  log_message "PASS: local_infile is disabled or not in use." "success"
else
  log_message "FAIL: local_infile should be disabled or not in use." "error"
fi

log_message  "4.5 Ensure mariadb is Not Started With 'skip-grant-tables' (Automated)"

skip_grant_tables=$(grep -E -i "skip[_-]grant[_-]tables" "$config_file" | grep -v "#" | awk -F "=" '{print $2}' | tr '[:upper:]' '[:lower:]')

if [[ -z $skip_grant_tables || $skip_grant_tables == "false" ]]; then
  log_message "PASS: MariaDB is not started with 'skip-grant-tables'." "success"
else
  log_message "FAIL: MariaDB is started with 'skip-grant-tables'." "error"
fi

log_message  "4.6 Ensure Symbolic Links are Disabled (Automated)"
# Execute the SQL statement to check the value of 'have_symlink'
have_symlink=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'have_symlink';" | awk 'NR>1 {print $2}')

if [[ $have_symlink == "DISABLED" ]]; then
  log_message "PASS: Symbolic links are disabled." "success"
else
  log_message "FAIL: Symbolic links are not disabled." "error"
fi

log_message  "4.7 Ensure the 'secure_file_priv' is Configured Correctly (Automated)"
# Execute the SQL statement to check the value of 'secure_file_priv'
secure_file_priv=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv';" | awk 'NR>1 {print $2}')

if [[ -z "$secure_file_priv" ]]; then
  log_message "FAIL: 'secure_file_priv' is set to an empty string." "error"
elif [[ "$secure_file_priv" == "NULL" ]]; then
  log_message "PASS: 'secure_file_priv' is disabled." "success"
else
  log_message "PASS: 'secure_file_priv' is configured with a valid path: $secure_file_priv" "success"
fi

log_message "4.8 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' (Automated)"
# Execute the SQL statement to check the value of 'sql_mode'
sql_mode=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'sql_mode';" | awk 'NR>1 {print $2}')

if [[ "$sql_mode" == *"STRICT_ALL_TABLES"* ]]; then
  log_message "PASS: 'sql_mode' contains 'STRICT_ALL_TABLES'." "success"
else
  log_message "FAIL: 'sql_mode' does not contain 'STRICT_ALL_TABLES'." "error"
fi

log_message  "4.9 Enable data-at-rest encryption in MariaDB (Automated)"
# Check if data-at-rest encryption is enabled
encryption_enabled=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_VALUE FROM information_schema.global_variables WHERE variable_name LIKE '%ENCRYPT%';" | awk 'NR>1 {print $1}')

if [[ "$encryption_enabled" == "OFF" ]]; then
  log_message "FAIL: Data-at-rest encryption is not enabled." "error"
else
  log_message "PASS: Data-at-rest encryption is enabled." "success"
  
  # List encrypted tablespaces
  encrypted_tablespaces=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT SPACE, NAME FROM INFORMATION_SCHEMA.INNODB_TABLESPACES_ENCRYPTION;" | awk 'NR>1 {print $1,$2}')

  if [[ -z "$encrypted_tablespaces" ]]; then
    log_message "FAIL: No encrypted tablespaces found." "error"
  else
    log_message "Encrypted tablespaces:"
    log_message "$encrypted_tablespaces"
  fi
fi

log_message  "5.1 Ensure Only Administrative Users Have Full Database Access (Manual)"
# Execute the SQL statement to check user privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT * FROM information_schema.user_privileges WHERE grantee NOT LIKE \"\'mysql.%localhost'\'\";")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: Only administrative users have full database access." "success"
else
  log_message "FAIL: Non-administrative users have full database access." "error"
  log_message "Non-administrative users:"
  log_message "$query_result"
fi

log_message  "5.2 Ensure 'FILE' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check FILE privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'FILE';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'FILE' privilege is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'FILE' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'FILE' privilege:"
  log_message "$query_result"
fi

log_message  "5.3 Ensure 'PROCESS' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check PROCESS privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'PROCESS';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'PROCESS' privilege is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'PROCESS' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'PROCESS' privilege:"
  log_message "$query_result"
fi

log_message  "5.4 Ensure 'SUPER' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check SUPER privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SUPER';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'SUPER' privilege is not granted to non-administrative users." "success"
else
  echlog_messageo "FAIL: 'SUPER' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'SUPER' privilege:"
  log_message "$query_result"
fi

log_message  "5.5 Ensure 'SHUTDOWN' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check SHUTDOWN privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'SHUTDOWN';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'SHUTDOWN' privilege is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'SHUTDOWN' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'SHUTDOWN' privilege:"
  log_message "$query_result"
fi

log_message  "5.6 Ensure 'CREATE USER' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check CREATE USER privileges
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'CREATE USER';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'CREATE USER' privilege is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'CREATE USER' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'CREATE USER' privilege:"
  log_message "$query_result"
fi

log_message  "5.7 Ensure 'GRANT OPTION' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check GRANT OPTION
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT DISTINCT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE = 'YES';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'GRANT OPTION' is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'GRANT OPTION' is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'GRANT OPTION':"
  log_message "$query_result"
fi

log_message  "5.8 Ensure 'REPLICATION SLAVE' is Not Granted to Non-Administrative Users (Manual)"
# Execute the SQL statement to check REPLICATION SLAVE privilege
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT GRANTEE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE = 'REPLICATION SLAVE';")

# Check if any non-administrative users are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: 'REPLICATION SLAVE' privilege is not granted to non-administrative users." "success"
else
  log_message "FAIL: 'REPLICATION SLAVE' privilege is granted to non-administrative users." "error"
  log_message "Non-administrative users with 'REPLICATION SLAVE' privilege:"
  log_message "$query_result"
fi

log_message  "5.9 Ensure DML/DDL Grants are Limited to Specific Databases and Users (Manual)"
# Execute the SQL statement to check DML/DDL grants
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT User, Host, Db FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y';")

# Check if any users have unrestricted DML/DDL privileges
if [[ -z "$query_result" ]]; then
  log_message "PASS: DML/DDL grants are limited to specific databases and users." "success"
else
  log_message "FAIL: DML/DDL grants are not limited to specific databases and users." "error"
  log_message "Users with unrestricted DML/DDL privileges:"
  log_message "$query_result"
fi

log_message  "5.10 Escaped and should be performed manually." "warning"


log_message  "6.1 Ensure 'log_error' is configured correctly (Automated)"
# Execute the SQL statement to get the value of 'log_error'
log_error=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW variables LIKE 'log_error';" | awk '{print $2}')

# Check if 'log_error' is configured correctly
if [[ "$log_error" != "./stderr.err" && "$log_error" != "" ]]; then
  log_message "PASS: 'log_error' is configured correctly." "success"
else
  log_message "FAIL: 'log_error' is not configured correctly." "error"
  log_message "Value of 'log_error': $log_error"
fi

log_message  "6.2 Ensure Log Files are Stored on a Non-System Partition (Automated)"
# Execute the SQL statement to get the value of 'log_bin_basename'
log_bin_basename=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT @@global.log_bin_basename;" | awk '{print $2}')

# Check if log files are stored on a non-system partition
if [[ "$log_bin_basename" != *"/var/"* && "$log_bin_basename" != *"/usr/"* && "$log_bin_basename" != "/"* ]]; then
  log_message "PASS: Log files are stored on a non-system partition." "success"
else
  log_message "FAIL: Log files are stored on a system partition." "error"
  log_message "Value of 'log_bin_basename': $log_bin_basename"
fi

log_message  "6.3 Ensure 'log_warnings' is Set to '2' (Automated)"
# Execute the SQL statement to get the value of 'log_warnings'
log_warnings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW GLOBAL VARIABLES LIKE 'log_warnings';" | awk 'NR> 1 {print $2}')

# Check if 'log_warnings' is set to '2'
if [[ "$log_warnings" == "2" ]]; then
  log_message "PASS: 'log_warnings' is set to '2'." "success"
else
  log_message "FAIL: 'log_warnings' is not set to '2'." "error"
  log_message "Value of 'log_warnings': $log_warnings"
fi

log_message  "6.4 Ensure Audit Logging Is Enabled (Automated)"
# Execute the SQL statement to check audit-related variables
audit_logging=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE '%audit%';")

# Check if the audit logging variables are configured properly
if [[ $audit_logging =~ "audit_log_format" && $audit_logging =~ "audit_log_policy" && $audit_logging =~ "audit_log_rotate_on_size" ]]; then
  log_message "PASS: Audit logging is enabled and properly configured." "success"
else
  log_message "FAIL: Audit logging is not enabled or not properly configured." "error"
  log_message "Audit logging variables:"
  log_message "$audit_logging"
fi

log_message  "6.5 Ensure the Audit Plugin Can't be Unloaded (Automated)"
# Execute the SQL statement to check the audit plugin load option
load_option=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT LOAD_OPTION FROM information_schema.plugins WHERE PLUGIN_NAME='SERVER_AUDIT';")

# Check if the load option is set to FORCE_PLUS_PERMANENT
if [[ $load_option == "FORCE_PLUS_PERMANENT" ]]; then
  log_message "PASS: Audit plugin cannot be unloaded." "success"
else
  log_message "FAIL: Audit plugin can be unloaded." "error"
  log_message "Audit plugin load option: $load_option"
fi

log_message  "6.6 Ensure Binary and Relay Logs are Encrypted (Automated)"
# Execute the SQL statement to check the encryption settings for binary and relay logs
encryption_settings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT VARIABLE_NAME, VARIABLE_VALUE, 'BINLOG - At Rest Encryption' as Note FROM information_schema.global_variables WHERE variable_name LIKE '%ENCRYPT_LOG%';")

# Check if the encryption setting is ON
if [[ $encryption_settings == *"ON"* ]]; then
  log_message "PASS: Binary and relay logs are encrypted." "success"
else
  log_message "FAIL: Binary and relay logs are not encrypted." "error"
  log_message "Encryption settings:"
  log_message "$encryption_settings"
fi

log_message  "7.1 Disable use of the mysql_old_password plugin (Automated)"
# Check if the mysql_old_password plugin is disabled for new passwords
password_setting=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES WHERE Variable_name = 'old_passwords';")

# Extract the value from the result
password_value=$(echo "$password_setting" | awk 'NR==2 {print $2}')

# Check if the value is set to OFF
if [[ $password_value == "OFF" ]]; then
  log_message "PASS: mysql_old_password plugin is disabled for new passwords." "success"
else
  log_message "FAIL: mysql_old_password plugin is not disabled for new passwords." "error"
  log_message"Password setting:"
  log_message "$password_setting"
fi

# Check if connections using mysql_old_password plugin are blocked
plugin_setting=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SHOW VARIABLES LIKE 'secure_auth';")

# Extract the value from the result
plugin_value=$(echo "$plugin_setting" | awk 'NR==2 {print $2}')

# Check if the value is set to YES
if [[ $plugin_value == "YES" ]]; then
  log_message "PASS: Connections using mysql_old_password plugin are blocked." "success"
else
  log_message "FAIL: Connections using mysql_old_password plugin are not blocked." "error"
  log_message "Plugin setting:"
  log_message "$plugin_setting"
fi

log_message  "7.2 Ensure Passwords are Not Stored in the Global Configuration (Automated)"
log_message "Escaped"
log_message "NOTICE: To assess this recommendation, perform the following steps:
1. Open the MariaDB configuration file (e.g., mariadb.cnf)
2. Examine the [client] section of the MariaDB configuration file and ensure password is not employed." "info"

log_message  "7.3 Ensure strong authentication is utilized for all accounts (Automated)"
# Execute the SQL query to find users utilizing specific plugins
query_result=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT User, host FROM mysql.user WHERE (plugin IN ('mysql_native_password', 'mysql_old_password', '') AND NOT authentication_string = 'invalid');")

# Check if any rows are returned
if [[ -z "$query_result" ]]; then
  log_message "PASS: Strong authentication is utilized for all accounts." "success"
else
  log_message "FAIL: Some accounts are not using strong authentication mechanisms." "error"
  log_message "Affected accounts:"
  log_message "$query_result"
fi

log_message  "7.4 Ensure Password Complexity Policies are in Place (Automated)"
# Check if plugin_load_add entries exist in the configuration file
if grep -q "plugin_load_add = simple_password_check" "$config_file" && grep -q "plugin_load_add = cracklib_password_check" "$config_file"; then
  log_message "PASS: Password complexity plugins are configured in the MariaDB configuration file." "success"
else
  log_message "FAIL: Password complexity plugins are not configured in the MariaDB configuration file." "error"
fi

# Check if simple_password_check and cracklib_password_check plugins are active
plugin_status=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" --defaults-extra-file="$config_file" -e "SHOW PLUGINS;")

if [[ $plugin_status == *"simple_password_check"*"ACTIVE"* ]] && [[ $plugin_status == *"cracklib_password_check"*"ACTIVE"* ]]; then
  log_message "PASS: Password complexity plugins (simple_password_check and cracklib_password_check) are active." "success"
else
  log_message "FAIL: Password complexity plugins (simple_password_check and cracklib_password_check) are not active." "error"
fi

# Check password policy settings
password_settings=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" --defaults-extra-file="$config_file" -e "SHOW VARIABLES LIKE '%pass%';")

minimal_length=$(echo "$password_settings" | awk '/simple_password_check_minimal_length/ {print $2}')
strict_validation=$(echo "$password_settings" | awk '/strict_password_validation/ {print $2}')
cracklib_dictionary=$(echo "$password_settings" | awk '/cracklib_password_check_dictionary/ {print $2}')

if [[ $minimal_length -ge 14 ]] && [[ $strict_validation == "ON" ]] && [[ $cracklib_dictionary != "" ]]; then
  log_message "PASS: Password policy settings are in place." "success"
else
  log_message "FAIL: Password policy settings are not configured correctly." "error"
  log_message "Password policy settings:"
  log_message "$password_settings"
fi

log_message  "7.5 Ensure No Users Have Wildcard Hostnames (Automated)"
# Execute SQL statement to check for wildcard hostnames
wildcard_users=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT user, host FROM mysql.user WHERE host = '%';" | tail -n +2)

# Check if any rows are returned
if [ -z "$wildcard_users" ]; then
  log_message "PASS: No users with wildcard hostnames found." "success"
else
  log_message "FAIL: Users with wildcard hostnames found:" "error"
  log_message "$wildcard_users"
fi

log_message  "7.6 Ensure No Anonymous Accounts Exist (Automated)"
# Execute SQL query to check for anonymous accounts
anonymous_accounts=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT user, host FROM mysql.user WHERE user = '';" | tail -n +2)

# Check if any rows are returned
if [ -z "$anonymous_accounts" ]; then
  log_message "PASS: No anonymous accounts found." "success"
else
  log_message "FAIL: Anonymous accounts found:" "error"
  log_message "$anonymous_accounts"
fi

log_message  "8.1 Ensure 'require_secure_transport' is Set to 'ON' and 'have_ssl' is Set to 'YES' (Automated)"
# Execute SQL query to check for anonymous accounts
anonymous_accounts=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e "SELECT user, host FROM mysql.user WHERE user = '';" | tail -n +2)

# Check if any rows are returned
if [ -z "$anonymous_accounts" ]; then
  log_message "PASS: No anonymous accounts found." "success"
else
  log_message "FAIL: Anonymous accounts found:" "error"
  log_message "$anonymous_accounts"
fi

log_message  "8.2 Ensure 'ssl_type' is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users (Automated)"
# Get remote users and their ssl_type
users=$(mysql -u"$username" -p"$password" -h"$host" -P"$port"  -Bse "SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');")

# Iterate over the result set
while read -r user host_feild ssl_type; do
  if [[ "$ssl_type" == "ANY" || "$ssl_type" == "X509" || "$ssl_type" == "SPECIFIED" ]]; then
    log_message "PASS: User '$user' on host '$host_feild' has ssl_type set to '$ssl_type'." "success"
  else
    log_message "FAIL: User '$user' on host '$host_feild' does not have ssl_type set to 'ANY', 'X509', or 'SPECIFIED'." "error"
  fi
done <<< "$users"

log_message  "8.3 Set Maximum Connection Limits for Server and per User (Manual)"
# Check global maximum connection limits
global_limits=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM information_schema.global_variables WHERE VARIABLE_NAME LIKE 'max_%connections';")
max_connections=$(echo "$global_limits" | grep "max_connections" | awk '{print $2}')
max_user_connections=$(echo "$global_limits" | grep "max_user_connections" | awk '{print $2}')

if [[ -z "$max_connections" || "$max_connections" == "0" ]]; then
  log_message "FAIL: No global maximum connection limit set." "error"
else
  log_message "PASS: Global maximum connection limit is set to $max_connections." "success"
fi

if [[ -z "$max_user_connections" || "$max_user_connections" == "0" ]]; then
  log_message "FAIL: No global maximum user connection limit set." "error"
else
  log_message "PASS: Global maximum user connection limit is set to $max_user_connections." "success"
fi

# Check user-specific maximum connection limits
user_limits=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SELECT user, host, max_connections, max_user_connections FROM mysql.user WHERE user NOT LIKE 'mysql.%' AND user NOT LIKE 'root';")

# Iterate over the result set
while read -r user host_feild max_conn max_user_conn; do
  if [[ "$max_conn" == "0" ]]; then
    log_message "FAIL: User '$user' on host '$host_feild' has no specific maximum connection limit set." "error"
  else
    log_message "PASS: User '$user' on host '$host_feild' has a maximum connection limit of $max_conn." "success"
  fi

  if [[ "$max_user_conn" == "0" ]]; then
    log_message "FAIL: User '$user' on host '$host_feild' has no specific maximum user connection limit set." "error"
  else
    log_message "PASS: User '$user' on host '$host_feild' has a maximum user connection limit of $max_user_conn." "success"
  fi
done <<< "$user_limits"

log_message  "9.1 Ensure Replication Traffic is Secured (Manual)"
# Check if replication is using SSL/TLS
ssl_allowed=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Allowed" | awk '{print $2}')

if [[ "$ssl_allowed" == "Yes" ]]; then
  log_message "PASS: Replication traffic is using SSL/TLS." "success"
else
  log_message "FAIL: Replication traffic is not using SSL/TLS." "error"
fi

# @todo Additional checks for private network, VPN, and SSH Tunnel can be added here

log_message  "9.2 Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' is enabled (Automated)"
# Check if replication is using SSL/TLS
ssl_allowed=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Allowed" | awk '{print $2}')

if [[ "$ssl_allowed" == "Yes" ]]; then
  # SSL/TLS is enabled, check if MASTER_SSL_VERIFY_SERVER_CERT is enabled
  verify_server_cert=$(mysql -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Verify_Server_Cert" | awk '{print $2}')

  if [[ "$verify_server_cert" == "Yes" ]]; then
    log_message "PASS: MASTER_SSL_VERIFY_SERVER_CERT is enabled for replication traffic." "success"
  else
    log_message "FAIL: MASTER_SSL_VERIFY_SERVER_CERT is not enabled for replication traffic." "error"
  fi
else
  log_message "NOTICE: Replication traffic is not secured with SSL/TLS. Skipping the check for MASTER_SSL_VERIFY_SERVER_CERT." "info"
fi

log_message  "9.3 Ensure 'super_priv' is Not Set to 'Y' for Replication Users (Automated)"
# Check if replication is using SSL/TLS
ssl_allowed=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Allowed" | awk '{print $2}')

if [[ "$ssl_allowed" == "Yes" ]]; then
  # SSL/TLS is enabled, check super_priv for replication users
  replication_users=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SELECT user FROM mysql.user WHERE Repl_slave_priv = 'Y';")

  while IFS= read -r user; do
    super_priv=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SELECT super_priv FROM mysql.user WHERE user = '$user';")

    if [[ "$super_priv" == "Y" ]]; then
      log_message "FAIL: Replication user '$user' has super_priv set to 'Y'." "error"
    else
      log_message "PASS: Replication user '$user' does not have super_priv set to 'Y'." "success"
    fi
  done <<< "$replication_users"

  # Check Master_SSL_Cipher setting
  master_ssl_cipher=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -e -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Cipher" | awk '{print $2}')

  if [[ -n "$master_ssl_cipher" ]]; then
    log_message "PASS: Master_SSL_Cipher is set to '$master_ssl_cipher' for replication traffic." "success"
  else
    log_message "FAIL: Master_SSL_Cipher is not set or empty for replication traffic." "error"
  fi
else
  log_message "NOTICE: Replication traffic is not secured with SSL/TLS. Skipping the check for 'super_priv' and Master_SSL_Cipher." "info"
fi

log_message  "9.4 Ensure only approved ciphers are used for Replication (Manual)"
# Check if replication is using SSL/TLS
ssl_allowed=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Allowed" | awk '{print $2}')

if [[ "$ssl_allowed" == "Yes" ]]; then
  # SSL/TLS is enabled, check SSL cipher configuration

  master_cipher=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Cipher" | awk '{print $2}')

  if [[ -n "$master_cipher" ]]; then
    echo "Master_SSL_Cipher: $master_cipher"

    # List of approved ciphers
    approved_ciphers=("AES128-SHA" "AES256-SHA" "AES128-SHA256" "AES256-SHA256")

    approved=1
    for cipher in $master_cipher; do
      if ! [[ "${approved_ciphers[@]}" =~ "$cipher" ]]; then
        approved=0
        log_message "FAIL: Unapproved cipher detected: $cipher" "error"
      fi
    done

    if [[ "$approved" == 1 ]]; then
      log_message "PASS: Only approved ciphers are used for replication." "success"
    fi
  else
    log_message "FAIL: Master_SSL_Cipher is not set. Replication traffic is not properly secured." "error"
  fi
else
  log_message "NOTICE: Replication traffic is not secured with SSL/TLS. Skipping the check for SSL cipher configuration." "info"
fi

log_message  "9.5 Ensure mutual TLS is enabled (Manual)"
# Check if replication is using SSL/TLS
ssl_allowed=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Allowed" | awk '{print $2}')

if [[ "$ssl_allowed" == "Yes" ]]; then
  # SSL/TLS is enabled, check mutual TLS configuration

  # Check REPLICA configuration
  replica_cert=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Cert" | awk '{print $2}')
  replica_key=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SHOW REPLICA STATUS\G;" | grep -i "Master_SSL_Key" | awk '{print $2}')

  if [[ -n "$replica_cert" && -n "$replica_key" ]]; then
    log_message "PASS: REPLICA is configured with mutual TLS. Certificate: $replica_cert, Key: $replica_key" "success"
  else
    log_message "FAIL: REPLICA is not properly configured with mutual TLS. Certificate and/or Key is missing." "error"
  fi

  # Check PRIMARY for replication users' ssl_type
  replication_users=$(mysql -Bse "SELECT user FROM mysql.user WHERE Repl_slave_priv = 'Y';")

  while IFS= read -r user; do
    ssl_type=$(mysql -u"$username" -p"$password" -h"$host" -P"$port" -Bse "SELECT ssl_type FROM mysql.user WHERE user = '$user';")

    if [[ "$ssl_type" == "X509" ]]; then
      log_message "PASS: Replication user '$user' has ssl_type set to 'X509'."
    else
      log_message "FAIL: Replication user '$user' does not have ssl_type set to 'X509'." "error"
    fi
  done <<< "$replication_users"
else
  log_message "NOTICE: Replication traffic is not secured with SSL/TLS. Skipping the check for mutual TLS configuration." "info"
fi


# End of script
log_message "Audit completed."

echo "Audit completed. Results are stored in $output_file."
done
