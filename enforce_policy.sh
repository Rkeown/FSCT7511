#!/bin/bash

# == File Permission Section ==
# store users with a UID >= 1000 into an array of users to check.
IFS=$'\n' usersToCheck=($(cat /etc/passwd | awk -F':' '( $3 >= 1000 ) {print $1}'))

#echo -e so echo will listen to the new line \n
echo -e "Normal users to check:\n" 
for i in ${usersToCheck[@]}; do
    echo -e "$i"
done
echo -e "\nChecking if user's home directories have the octal permissions of 700...\n"
  echo "$(date '+%Y-%m-%d %H:%M:%S' ) - Checking users' directory permissions" >> /tmp/remediation.log
#I couldn't think of a better way to print the users and then check permissions and whatnot as seen below
for i in ${usersToCheck[@]}; do
    #converts the output of the eval echo ~$i command into a string with the value of the current user's home directory path
    # this way the string can be used with the stat -c %a command to print the octal value of the directory's permissions
    #  grep is then used to test if the output is not equal (-v) to 700
    dirToCheck=$(eval echo ~$i)
    if [ -d "$dirToCheck" ]; then
        if stat -c %a $dirToCheck | grep -v "700" &> /dev/null; then
            echo -e "User: $i's home directory permissions are not 700"
            echo "$(date '+%Y-%m-%d %H:%M:%S' ) - WARNING: $i's home directory permissions is not 700" >> /tmp/remediation.log
            if [ "$i" != "rory" ]; then
            
            echo -e "\nChanging permissions of $dirToCheck to 700. Sudo password may be required."
            sudo chmod 700 $dirToCheck
            echo "User's $i home directory permissions updated to 700" 
            echo "User's $i home directory permissions updated to 700" >> /tmp/remediation.log
            fi
    else
        echo "User: $i's home permissions are already 700"
        fi
    else
        echo -e "User: $i does not have a home directory"
    fi
done

echo "$(date '+%Y-%m-%d %H:%M:%S' ) - checking /etc/passwd and /etc/shadow permissions are 644 and 640 respectively"  >> /tmp/remediation.log
# checking /etc/passd and /etc/shadow permissions using the same method as before
echo -e "\nChecking /etc/passwd and /etc/shadow permissions...\n"
if stat -c %a /etc/passwd | grep -v "644" &> /dev/null; then
    echo "/etc/passwd permissions are not 644"
    sudo chmod 644 /etc/passwd
    echo "$(date '+%Y-%m-%d %H:%M:%S' ) - WARNING: /etc/passwd permissions were set to 644 as they deviated from this standard" >> /tmp/remediation.log

elif stat -c %a /etc/shadow | grep -q "640" &> /dev/null; then
    echo "/etc/passwd permissions are already set to 644"
fi

if stat -c %a /etc/shadow | grep -v "640" &> /dev/null; then
    echo "/etc/shadow permissions are not 640"
    sudo chmod 640 /etc/shadow
    echo "$(date '+%Y-%m-%d %H:%M:%S' ) - WARNING: /etc/shadow permissions were set to 640 as they deviated from this standard" >> /tmp/remediation.log

elif stat -c %a /etc/shadow | grep -q "640" &> /dev/null; then
    echo "/etc/shadow permissions are already set to 640"
fi

#== Account Permission Section ==

#Checking wheel membership
echo -e "\nChecking whether wheel or sudo group exists..."
if getent group | grep "wheel" &> /dev/null; then
    echo "wheel group exists"
    IFS=$',' groupMembers=($(awk -F':' '/wheel/{print $4}' /etc/group))
    wheelOrSudo="wheel"

elif getent group | grep "sudo" &> /dev/null; then
    echo "sudo group exists"
    IFS=$',' groupMembers=($(awk -F':' '/sudo/{print $4}' /etc/group))
    wheelOrSudo="sudo"
fi
echo "$(date '+%Y-%m-%d %H:%M:%S' ) - checking $wheelOrSudo members" >> /tmp/remediation.log
echo "$wheelOrSudo members:"
for i in ${groupMembers[@]}; do
    echo "- $i"
done

if [[ "${groupMembers[*]}" =~  ^rory$ ]]; then
    echo "No unexpected $wheelOrSudo members"

else
    echo "ALERT unexpected user(s) in $wheelOrSudo:"
    echo "$(date '+%Y-%m-%d %H:%M:%S' ) - WARNING: unexpected memebers of $wheelOrSudo group" >> /tmp/remediation.log
    echo "$(date '+%Y-%m-%d %H:%M:%S' ) - WARNING: unexpected memebers of $wheelOrSudo group:" >> /tmp/alert_report.txt
    for i in ${groupMembers[@]}; do
        if ! [[ "$i" =~ ^rory$ ]]; then
            echo "- $i"
            echo "- $i" >> /tmp/remediation.log
            echo "- $i" >> /tmp/alert_report.txt
        fi
    done 
fi
echo "$(date '+%Y-%m-%d %H:%M:%S' ) - Checking password aging settings" >> /tmp/remediation.log
# == Account Security Section ==
echo -e "\nChecking Security Settings...\n"

# Password Aging settings
echo "Password aging settings of users:"
for i in ${usersToCheck[@]}; do
    echo -e "\n- Password info for $i:\n"
    sudo chage -l "$i"
done
echo -e "\nPassword aging and history configuration:"
cat /etc/login.defs | grep -w "PASS_MAX_DAYS" | grep -v "#"
echo -e "\nAccount lockout settings:"
cat /etc/security/faillock.conf | grep -w "deny"
cat /etc/security/faillock.conf | grep -w "unlock_time" | grep -v "is the same"
cat /etc/security/faillock.conf | grep -w "fail_interval"
echo ""
if [ -f /tmp/remediation.log]; then
    echo "/tmp/remediation.log exists"

else
    echo "No remediation log exists under /tmp/remediation.log"
    
fi
echo "$(date '+%Y-%m-%d %H:%M:%S' ) - Checking SELinux settings" >> /tmp/remediation.log
echo getenforce >> /tmp/remediation.log
echo ""
# SELinux mode
echo -n "SELinux status: " ; getenforce
