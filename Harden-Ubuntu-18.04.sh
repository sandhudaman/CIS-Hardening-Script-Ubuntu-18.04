#!/bin/bash

# CIS Ubuntu Linux 18.04 LTS Benchmark v1.0.0 - Level 1 & 2

# 1.1.1 - Ensure mounting of cramfs filesystems is disabled
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

# 1.1.8 - Ensure nodev option set on /tmp partition
sed -i -e 's/^.*\/tmp.*$/tmpfs \/tmp tmpfs defaults,noexec,nosuid,nodev 0 0/g' /etc/fstab
mount -o remount /tmp

# 1.1.9 - Ensure nosuid option set on /tmp partition
sed -i -e 's/^.*\/var\/tmp.*$/tmpfs \/var\/tmp tmpfs defaults,noexec,nosuid,nodev 0 0/g' /etc/fstab
mount -o remount /var/tmp

# 1.5.1 - Ensure permissions on /etc/grub.d are configured
chown -R root:root /etc/grub.d/
chmod -R og-rwx /etc/grub.d/

# 1.7.1.2 - Ensure GDM login banner is configured
echo "banner-message-enable=true" >> /etc/gdm3/greeter.dconf-defaults
echo "banner-message-text='Authorized access only. All activity may be monitored and reported.'" >> /etc/gdm3/greeter.dconf-defaults

# 2.1.1 - Ensure xinetd is not installed
apt-get remove xinetd -y

# 2.1.2 - Ensure openbsd-inetd is not installed
apt-get remove openbsd-inetd -y

# 2.2.1.1 - Ensure time synchronization is in use
apt-get install ntp -y
systemctl enable ntp
systemctl start ntp

# 2.2.1.4 - Ensure ntp is configured
sed -i -e 's/^.*restrict.*$/restrict default kod nomodify notrap nopeer noquery/' /etc/ntp.conf
sed -i -e 's/^.*server.*$/server time.google.com/' /etc/ntp.conf

# 2.2.2 - Ensure X Window System is not installed
apt-get remove xserver-xorg* -y

# 2.3.1 - Ensure NIS Client is not installed
apt-get remove nis -y

# 2.3.4 - Ensure rsh client is not installed
apt-get remove rsh-client -y

# 2.3.5 - Ensure talk client is not installed
apt-get remove talk -y

# 2.3.6 - Ensure telnet client is not installed
apt-get remove telnet -y

# 3.1 - Ensure IP forwarding is disabled
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0

# 3.2.2 - Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0

# 3.2.3 - Ensure ICMP redirects are not accepted
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0

# 3.2.4 - Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.secure_redirects = 0" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv6.conf.all.secure_redirects=0

# 3.2.5 - Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.all.log_martians = 1" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv6.conf.all.log_martians=1

# 3.3.2 - Ensure TCP SYN Cookies is enabled
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1

# 3.4.1 - Ensure TCP Wrappers is installed
apt-get install tcpd -y

# 4.1.1.1 - Ensure auditd is installed
apt-get install auditd -y

# 4.1.1.4 - Ensure events that modify date and time information are collected
echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/rules.d/time.rules
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/

# 4.1.2 - Ensure auditd collects login and logout events
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/logins.rules
echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/logins.rules

# 4.1.4 - Ensure events that modify user/group information are collected
echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/rules.d/identity.rules
echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/identity.rules

# 4.1.5 - Ensure events that modify the system's network environment are collected
echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules
echo "-w /etc/network -p wa -k system-locale" >> /etc/audit/rules.d/system-locale.rules

# 4.1.6 - Ensure events that modify the system's Mandatory Access Controls are collected
echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/rules.d/MAC-policy.rules

# 5.1.3 - Ensure password creation requirements are configured
sed -i 's/^\(password.*pam_pwquality\.so.*\)$/# \1/' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so retry=3" >> /etc/pam.d/common-password
echo "password requisite pam_pwquality.so minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
echo "password requisite pam_pwquality.so enforce_for_root" >> /etc/pam.d/common-password
echo "password required pam_pwhistory.so remember=24" >> /etc/pam.d/common-password

# 5.2.1 - Ensure password expiration is 365 days or less
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t365/' /etc/login.defs

# 5.2.2 - Ensure minimum days between password changes is 7 or more
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs

# 5.2.3 - Ensure password expiration warning days is 7 or more

sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t7/' /etc/login.defs

# 6.1.2 - Ensure permissions on /etc/shadow are configured
chown root:shadow /etc/shadow
chmod 000 /etc/shadow

# 6.1.4 - Ensure permissions on /etc/gshadow are configured
chown root:shadow /etc/gshadow
chmod 000 /etc/gshadow

# 6.1.6 Ensure permissions on /etc/passwd are configured
chown root:root /etc/passwd
chmod 644 /etc/passwd

# 6.1.7 - Ensure permissions on /etc/group are configured
chown root:root /etc/group
chmod 644 /etc/group

# 6.1.8 - Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chmod u-x,go-rwx /etc/shadow-

# 6.1.9 - Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chmod u-x,go-rwx /etc/gshadow-

# 6.1.10 - Ensure no world writable files exist
find / -xdev -type f -perm -0002 -exec chmod o-w {} \;

# 6.1.11 - Ensure no unowned files or directories exist
find / -xdev -nouser -o -nogroup -exec chown root:root {} \;

# 6.1.12 - Ensure no ungrouped files or directories exist
find / -xdev -nogroup -exec chown root:root {} \;

# 6.1.13 - Audit SUID executables
find / -xdev -type f -perm -4000 -exec chmod u-s {} \;
find / -xdev -type f -perm -4000 -print | awk -F/ '{print $NF}' | while read i; do
  egrep "^$i$" /etc/cron.daily/aide > /dev/null || echo $i >> /etc/cron.daily/aide
done

