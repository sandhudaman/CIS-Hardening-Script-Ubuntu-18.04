#!/bin/bash

# 1.1.1.1 - 1.1.1.6 - Ensure mounting of certain filesystems is disabled
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf

# 1.1.2 - Ensure /tmp is configured
if ! grep -q "^\s*tmpfs\s*/tmp\s" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults 0 0" >> /etc/fstab
fi

# 1.1.3 - Ensure nodev option set on /tmp partition
if ! grep -q "^\s*tmpfs\s*/tmp\s" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,nodev 0 0" >> /etc/fstab
else
  sed -i 's/\(^\s*tmpfs\s*\/tmp\s*\)\(.*\)/\1defaults,nodev\2/' /etc/fstab
fi

# 1.1.4 - Ensure nosuid option set on /tmp partition
if ! grep -q "^\s*tmpfs\s*/tmp\s" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,nodev,nosuid 0 0" >> /etc/fstab
else
  sed -i 's/\(^\s*tmpfs\s*\/tmp\s*\)\(.*\)/\1defaults,nodev,nosuid\2/' /etc/fstab
fi

# 1.1.5 - Ensure noexec option set on /tmp partition
if ! grep -q "^\s*tmpfs\s*/tmp\s" /etc/fstab; then
  echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
else
  sed -i 's/\(^\s*tmpfs\s*\/tmp\s*\)\(.*\)/\1defaults,nodev,nosuid,noexec\2/' /etc/fstab
fi

# 1.1.6 - Ensure /dev/shm is configured
if ! grep -q "^\s*tmpfs\s*/dev/shm\s" /etc/fstab; then
  echo "tmpfs /dev/shm tmpfs defaults 0 0" >> /etc/fstab
fi

# 1.1.7 - Ensure nodev option set on /dev/shm partition
if ! grep -q "^\s*tmpfs\s*/dev/shm\s" /etc/fstab; then
  echo "tmpfs /dev/shm tmpfs defaults,nodev 0 0" >> /etc/fstab
else
  sed -i 's/\(^\s*tmpfs\s*\/dev\/shm\s*\)\(.*\)/\1defaults,nodev\2/' /etc/fstab
fi

# 1.1.8 Ensure nosuid option set on /dev/shm partition
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
mount -o remount,nosuid /dev/shm

# 1.1.9 Ensure noexec option set on /dev/shm partition
mount -o remount,noexec /dev/shm

# 1.1.10 Ensure separate partition exists for /var
echo "LABEL=/var /var ext4 defaults,nodev,nosuid 0 0" >> /etc/fstab
mount -o remount,nodev,nosuid /var

# 1.1.11 Ensure separate partition exists for /var/tmp
echo "tmpfs /var/tmp tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
mount -o remount,nodev,nosuid,noexec /var/tmp

# 1.1.12 Ensure /var/tmp partition includes the nodev option
mount -o remount,nodev /var/tmp

# 1.1.13 Ensure /var/tmp partition includes the nosuid option
mount -o remount,nosuid /var/tmp

# 1.1.14 Ensure /var/tmp partition includes the noexec option
mount -o remount,noexec /var/tmp

# 1.1.15 - Ensure separate partition exists for /var/log
if grep -q "^[^#].*/var/log " /etc/fstab ; then
  echo "Partition already exists for /var/log"
else
  echo "Creating partition for /var/log"
  mkdir /var/log.old
  mv /var/log/* /var/log.old/
  echo "/dev/sda5 /var/log ext4 defaults 0 0" >> /etc/fstab
  mount -a
fi

# 1.1.16 - Ensure separate partition exists for /var/log/audit
if grep -q "^[^#].*/var/log/audit " /etc/fstab ; then
  echo "Partition already exists for /var/log/audit"
else
  echo "Creating partition for /var/log/audit"
  mkdir /var/log/audit.old
  mv /var/log/audit/* /var/log/audit.old/
  echo "/dev/sda6 /var/log/audit ext4 defaults 0 0" >> /etc/fstab
  mount -a
fi

# 1.1.17 - Ensure separate partition exists for /home
if grep -q "^[^#].*/home " /etc/fstab ; then
  echo "Partition already exists for /home"
else
  echo "Creating partition for /home"
  mkdir /home.old
  mv /home/* /home.old/
  echo "/dev/sda7 /home ext4 defaults 0 0" >> /etc/fstab
  mount -a
fi

# 1.1.18 - Ensure /home partition includes the nodev option
if grep -q "^[^#].*/home " /etc/fstab && grep -q "^[^#].*/home " /etc/fstab | grep -q nodev ; then
  echo "nodev option already exists for /home partition"
else
  echo "Adding nodev option for /home partition"
  sed -i 's/.*\/home.*/&\,nodev/' /etc/fstab
  mount -a
fi

# 1.1.19 - Ensure nodev option set on removable media partitions
echo "ACTION==\"add\", KERNEL==\"sd*\", ATTR{removable}==\"1\", RUN+=\"/bin/mount -o nodev,noexec,nosuid /dev/%k /mnt/usb\"" >> /etc/udev/rules.d/10-usb.rules

# 1.1.20 - Ensure nosuid option set on removable media partitions
echo "ACTION==\"add\", KERNEL==\"sd*\", ATTR{removable}==\"1\", RUN+=\"/bin/mount -o nodev,noexec,nosuid /dev/%k /mnt/usb\"" >> /etc/udev/rules.d/10-usb.rules

# 1.1.21 - Ensure noexec option set on removable media partitions
echo "ACTION==\"add\", KERNEL==\"sd*\", ATTR{removable}==\"1\", RUN+=\"/bin/mount -o nodev,noexec,nosuid /dev/%k /mnt/usb\"" >> /etc/udev/rules.d/10-usb.rules

# 1.1.22 - Ensure sticky bit is set on all world-writable directories
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod a+t {} \;



# 1.1.23 Disable Automounting
echo "install cramfs /bin/true" >> /etc/modprobe.d/cramfs.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/freevxfs.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/jffs2.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/hfs.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/hfsplus.conf
echo "install udf /bin/true" >> /etc/modprobe.d/udf.conf

# 1.1.24 Disable USB Storage
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf

# 1.2.1 Ensure package manager repositories are configured
echo "deb http://archive.ubuntu.com/ubuntu bionic main" > /etc/apt/sources.list
echo "deb http://archive.ubuntu.com/ubuntu bionic-updates main" >> /etc/apt/sources.list
echo "deb http://security.ubuntu.com/ubuntu bionic-security main" >> /etc/apt/sources.list

# 1.2.2 Ensure GPG keys are configured
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32

# 1.3.1 Ensure AIDE is installed
apt-get -y install aide

# 1.3.2 Ensure filesystem integrity is regularly checked
echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" >> /etc/crontab

# 1.4.1 Ensure permissions on bootloader config are not overridden
chattr +i /boot/grub/grub.cfg

# 1.4.2 Ensure bootloader password is set
echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 root <password_hash>" >> /etc/grub.d/40_custom
update-grub

# 1.4.3 Ensure permissions on bootloader config are configured
chmod 600 /boot/grub/grub.cfg

# 1.4.4 Ensure authentication required for single user mode
sed -i 's/splash quiet//g' /etc/default/grub
echo "exec sulogin" >> /usr/lib/systemd/system/rescue.service
update-grub

# 1.5.1 Ensure XD/NX support is enabled
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

# 1.5.2 Ensure address space layout randomization (ASLR) is enabled (Automated)
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

# 1.5.3 Ensure prelink is disabled (Automated)
prelink -ua
apt-get remove prelink -y

# 1.5.4 Ensure core dumps are restricted (Automated)
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
echo "kernel.core_uses_pid = 1" >> /etc/sysctl.conf

# 1.6.1.1 Ensure AppArmor is installed (Automated)
apt-get install apparmor -y

# 1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration (Automated)
sed -i 's/GRUB_CMDLINE_LINUX="/&apparmor=1 security=apparmor /' /etc/default/grub
update-grub

# 1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode (Automated)
aa-enforce /etc/apparmor.d/*
aa-complain /etc/apparmor.d/*-*
aa-complain /usr/bin/man
aa-complain /usr/sbin/nscd
aa-complain /usr/sbin/tcpdump

# 1.6.1.4 Ensure all AppArmor Profiles are enforcing (Automated)
aa-enforce /etc/apparmor.d/*

# 1.7.1 Ensure message of the day is configured properly (Automated)
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd

# 1.7.2 Ensure permissions on /etc/issue.net are configured (Automated)
chown root:root /etc/issue.net
chmod 644 /etc/issue.net

# 1.7.3 Ensure permissions on /etc/issue are configured (Automated)
chown root:root /etc/issue
chmod 644 /etc/issue

# 1.7.4 Ensure permissions on /etc/motd are configured (Automated)
chown root:root /etc/motd
chmod 644 /etc/motd

# 1.7.5 Ensure remote login warning banner is configured properly (Automated)
echo "Warning: Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

# 1.7.6 Ensure local login warning banner is configured properly (Automated)
echo "Warning: Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd

# 1.8.1 Ensure GNOME Display Manager is removed (Manual)
apt-get remove gdm3 -y

# 1.8.2 Ensure GDM login banner is configured (Automated)
echo "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" >> /etc/gdm3/greeter.dconf-defaults

# 1.8.3 Ensure disable-user-list is enabled (Automated)
echo "disable-user-list=true" >> /etc/gdm3/greeter.dconf-defaults

# 1.8.4 Ensure XDCMP is not enabled (Automated)
echo "DisallowTCP=true" >> /etc/gdm3/custom.conf

# 1.9 Ensure updates, patches, and additional security software are installed (Manual)
apt-get update && apt-get upgrade


# 2.1.1.1 Ensure time synchronization is in use (Automated)
timedatectl set-ntp true

# 2.1.1.2 Ensure systemd-timesyncd is configured (Manual)
sed -i 's/#NTP=/NTP=0.ubuntu.pool.ntp.org 1.ubuntu.pool.ntp.org 2.ubuntu.pool.ntp.org 3.ubuntu.pool.ntp.org/g' /etc/systemd/timesyncd.conf

# 2.1.1.3 Ensure chrony is configured (Automated)
apt-get install -y chrony
systemctl enable chrony
sed -i 's/^pool/#pool/g' /etc/chrony/chrony.conf
echo "server time.google.com iburst" >> /etc/chrony/chrony.conf

# 2.1.1.4 Ensure ntp is configured (Automated)
apt-get install -y ntp
systemctl enable ntp
sed -i 's/^pool/#pool/g' /etc/ntp.conf
echo "server time.google.com iburst" >> /etc/ntp.conf

# 2.1.2 Ensure X Window System is not installed (Automated)
apt-get remove -y xserver-xorg*

# 2.1.3 Ensure Avahi Server is not installed (Automated)
apt-get remove -y avahi-daemon

# 2.1.4 Ensure CUPS is not installed (Automated)
apt-get remove -y cups

# 2.2.1 Ensure NIS Client is not installed (Automated)
apt-get remove -y nis

# 2.2.2 Ensure rsh client is not installed (Automated)
apt-get remove -y rsh-client

# 2.2.3 Ensure talk client is not installed (Automated)
apt-get remove -y talk

# 2.2.4 Ensure telnet client is not installed (Automated)
apt-get remove -y telnet

# 2.2.5 Ensure LDAP client is not installed (Automated)
apt-get remove -y ldap-utils

# 2.2.6 Ensure RPC is not installed (Automated)
apt-get remove -y rpcbind

# 2.3 Ensure nonessential services are removed or masked (Manual)
# Check and disable services that are not needed
systemctl list-unit-files | grep enabled | egrep -i 'dhcp|cups|avahi|postfix|smb|nfs|apache2|bind9|vsftpd|dovecot|samba|nscd|telnet|ssh|ftp' | awk '{print $1}' | xargs -I {} systemctl disable {}

# 3.1.1 Disable IPv6 (Manual)
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.d/99-sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6=1" >> /etc/sysctl.d/99-sysctl.conf
sysctl -p

# 3.1.2 Ensure wireless interfaces are disabled (Automated)
rfkill list all | grep -w "Wireless LAN" | grep -w "yes" | awk '{print $1}' | xargs -I {} rfkill block {}

# 3.2.1 Ensure packet redirect sending is disabled
echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# 3.2.2 Ensure IP forwarding is disabled
echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf
echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.forwarding=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.conf.all.forwarding=0
sysctl -w net.ipv6.conf.default.forwarding=0

# 3.3.1 Ensure source routed packets are not accepted
echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# 3.3.2 Ensure ICMP redirects are not accepted
echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# 3.3.3 Ensure secure ICMP redirects are not accepted
echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0

# 3.3.4 Ensure suspicious packets are logged
echo "net.ipv4.conf.all.log_martians=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1

# 3.3.5 Ensure broadcast ICMP requests are ignored
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

# 3.3.6 Ensure bogus ICMP responses are ignored
echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

# 3.3.7 Ensure Reverse Path Filtering is enabled (Automated)
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.arp_announce=2" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.arp_announce=2" >> /etc/sysctl.conf

# 3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

# 3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)
echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.conf

# 3.4.1 Ensure DCCP is disabled (Automated)
echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf

# 3.4.2 Ensure SCTP is disabled (Automated)
echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf

# 3.4.3 Ensure RDS is disabled (Automated)
echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf

# 3.4.4 Ensure TIPC is disabled (Automated)
echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

# 3.5.1.1 Ensure ufw is installed (Automated)
apt-get -y install ufw

# 3.5.1.2 Ensure iptables-persistent is not installed with ufw (Automated)
apt-get -y purge iptables-persistent

# 3.5.1.3 Ensure ufw service is enabled (Automated)
systemctl enable ufw

# 3.5.1.4 Ensure ufw loopback traffic is configured (Automated)
ufw allow in on lo

# 3.5.1.5 Ensure ufw outbound connections are configured (Manual)
# Allow all outbound traffic by default
ufw default allow outgoing

# 3.5.1.6 Ensure ufw firewall rules exist for all open ports (Manual)
# Example: Allow incoming SSH traffic
ufw allow ssh

# 3.5.1.7 Ensure ufw default deny firewall policy (Automated)
ufw default deny incoming

# 3.5.2.1 Ensure nftables is installed (Automated)
apt-get -y install nftables

# 3.5.2.2 Ensure ufw is uninstalled or disabled with nftables (Automated)
apt-get -y purge ufw
systemctl stop ufw
systemctl disable ufw

# 3.5.2.3 Ensure iptables are flushed with nftables (Manual)
iptables -F

# 3.5.2.4 Ensure a nftables table exists (Automated)
nft list tables > /dev/null 2>&1
if [[ $? -ne 0 ]]; then
  nft add table inet filter
fi

# 3.5.2.5 Ensure nftables base chains exist (Automated)
nft list table inet filter | grep -q 'chain input {'
if [[ $? -ne 0 ]]; then
  nft add chain inet filter input { type filter hook input priority 0 \; }
fi

nft list table inet filter | grep -q 'chain forward {'
if [[ $? -ne 0 ]]; then
  nft add chain inet filter forward { type filter hook forward priority 0 \; }
fi

nft list table inet filter | grep -q 'chain output {'
if [[ $? -ne 0 ]]; then
  nft add chain inet filter output { type filter hook output priority 0 \; }
fi

# 3.5.2.6 Ensure nftables loopback traffic is configured (Automated)
nft list ruleset | grep -q 'iif lo accept'
if [[ $? -ne 0 ]]; then
  nft insert rule inet filter input iif lo accept
  nft insert rule inet filter output oif lo accept
fi

# 3.5.2.7 Ensure nftables outbound and established connections are configured (Manual)
nft list ruleset | grep -q 'tcp flags & (fin|syn|rst|ack) == syn counter'
if [[ $? -ne 0 ]]; then
  nft add rule inet filter output tcp flags & \(fin|syn|rst|ack\) == syn counter packets 0 bytes 0
fi

nft list ruleset | grep -q 'tcp flags & (fin|syn|rst|ack) == syn limit rate over 25/minute burst 100 packets counter packets 0 bytes 0'
if [[ $? -ne 0 ]]; then
  nft add rule inet filter output tcp flags & \(fin|syn|rst|ack\) == syn limit rate over 25/minute burst 100 packets counter packets 0 bytes 0
fi

nft list ruleset | grep -q 'ct state established,related accept'
if [[ $? -ne 0 ]]; then
  nft add rule inet filter input ct state established,related accept
  nft add rule inet filter output ct state established,related accept
fi

# 3.5.2.8 Ensure nftables default deny firewall policy (Automated)
nft list ruleset | grep -q 'type filter hook'
if [[ $? -ne 0 ]]; then
  nft add rule inet filter input reject with icmpx type port-unreachable
  nft add rule inet filter output reject with icmpx type port-unreachable
  nft add rule inet filter forward reject with icmpx type port-unreachable
fi

# 3.5.2.9 Ensure nftables service is enabled (Automated)
systemctl enable nftables.service

# 3.5.2.10 Ensure nftables rules are permanent (Automated)
nft list ruleset > /etc/nftables.conf

# 3.5.3.1.1 Ensure iptables packages are installed (Automated)
apt-get install -y iptables


# Ensure nftables is not installed with iptables
if dpkg -s "iptables" >/dev/null 2>&1 && dpkg -s "nftables" >/dev/null 2>&1; then
    echo "Error: Both iptables and nftables are installed. Please remove one of them." >&2
    exit 1
fi

# Ensure ufw is uninstalled or disabled with iptables
if dpkg -s "ufw" >/dev/null 2>&1 && dpkg -s "iptables" >/dev/null 2>&1; then
    if systemctl is-enabled ufw >/dev/null 2>&1; then
        echo "Disabling ufw service"
        systemctl disable ufw
    fi
    echo "Uninstalling ufw"
    apt-get remove ufw -y
fi

# Ensure iptables default deny firewall policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Ensure iptables loopback traffic is configured
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Ensure iptables outbound and established connections are configured
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Ensure iptables firewall rules exist for all open ports
# Replace [PORT] with the actual port number
iptables -A INPUT -p tcp --dport [PORT] -j ACCEPT

# Ensure ip6tables outbound and established connections are configured
ip6tables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Ensure ip6tables firewall rules exist for all open ports
# Replace [PORT] with the actual port number
ip6tables -A INPUT -p tcp --dport [PORT] -j ACCEPT

# Ensure journald is configured to send logs to rsyslog
mkdir -p /etc/systemd/journald.conf.d
echo "[Journal]" >> /etc/systemd/journald.conf.d/99-prod.conf
echo "ForwardToSyslog=yes" >> /etc/systemd/journald.conf.d/99-prod.conf

# Ensure journald is configured to compress large log files
sed -i 's/#Compress/Compress/g' /etc/systemd/journald.conf

# Ensure journald is configured to write logfiles to persistent disk
sed -i 's/#Storage/Storage/g' /etc/systemd/journald.conf

#!/bin/bash

# 4.2.3 Ensure permissions on all logfiles are configured (Automated)
find /var/log -type f -exec chmod g-wx,o-rwx {} +

# 4.3 Ensure logrotate is configured (Manual)
# Verify that logrotate is installed
if [ ! -x "$(command -v logrotate)" ]; then
  echo 'logrotate is not installed. Install it using "apt install logrotate".' >&2
  exit 1
fi

# 4.4 Ensure logrotate assigns appropriate permissions (Automated)
# Update the permissions of the logrotate configuration file
chmod 0640 /etc/logrotate.conf

# 5.1.1 Ensure cron daemon is enabled and running (Automated)
systemctl enable cron
systemctl start cron

# 5.1.2 Ensure permissions on /etc/crontab are configured (Automated)
chmod 0600 /etc/crontab

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Automated)
chmod -R 0700 /etc/cron.hourly

# 5.1.4 Ensure permissions on /etc/cron.daily are configured (Automated)
chmod -R 0700 /etc/cron.daily

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Automated)
chmod -R 0700 /etc/cron.weekly

# 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Automated)
chmod -R 0700 /etc/cron.monthly

# 5.1.7 Ensure permissions on /etc/cron.d are configured (Automated)
chmod -R 0700 /etc/cron.d


# 5.1.8 Ensure cron is restricted to authorized users
echo "root" > /etc/cron.allow
chown root:root /etc/cron.allow
chmod 600 /etc/cron.allow

# 5.1.9 Ensure at is restricted to authorized users
echo "root" > /etc/at.allow
chown root:root /etc/at.allow
chmod 600 /etc/at.allow

# 5.2.1 Ensure sudo is installed
apt-get install sudo -y

# 5.2.2 Ensure sudo commands use pty
sed -i 's/Defaults.*requiretty/#Defaults    requiretty/g' /etc/sudoers

# 5.2.3 Ensure sudo log file exists
touch /var/log/sudo.log
chown root:adm /var/log/sudo.log
chmod 0640 /var/log/sudo.log
sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/g' /etc/sudoers
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/sudoers
sed -i 's/^Defaults.*logfile=.*$/Defaults logfile=\/var\/log\/sudo.log/g' /etc/sudoers

# 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured
chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# 5.3.2 Ensure permissions on SSH private host key files are configured
chmod 0600 /etc/ssh/ssh_host_rsa_key
chmod 0600 /etc/ssh/ssh_host_ecdsa_key
chmod 0600 /etc/ssh/ssh_host_ed25519_key

# 5.3.3 Ensure permissions on SSH public host key files are configured
chmod 0644 /etc/ssh/ssh_host_rsa_key.pub
chmod 0644 /etc/ssh/ssh_host_ecdsa_key.pub
chmod 0644 /etc/ssh/ssh_host_ed25519_key.pub


#Please note that the script assumes the use of a non-root user with sudo privileges. 
#Replace <username> with the username of the non-root user you have set up. 
#Also, remember to review and test the script before running it on your system.

# 5.3.4 Ensure SSH access is limited
sed -i 's/#PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#MaxAuthTries.*/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/#MaxSessions.*/MaxSessions 4/g' /etc/ssh/sshd_config
echo "AllowUsers <username>" >> /etc/ssh/sshd_config

# 5.3.5 Ensure SSH LogLevel is appropriate
echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config

# Restart SSH service
systemctl restart ssh

#!/bin/bash

# 5.1.8 Ensure cron is restricted to authorized users (Automated)
touch /etc/cron.allow
chmod 600 /etc/cron.allow
chown root:root /etc/cron.allow
echo "root" > /etc/cron.allow

# 5.1.9 Ensure at is restricted to authorized users (Automated)
touch /etc/at.allow
chmod 600 /etc/at.allow
chown root:root /etc/at.allow
echo "root" > /etc/at.allow

# 5.2.1 Ensure sudo is installed (Automated)
apt-get install sudo -y

# 5.2.2 Ensure sudo commands use pty (Automated)
sed -i "s/^Defaults[ ]*requiretty/# Defaults requiretty/g" /etc/sudoers

# 5.2.3 Ensure sudo log file exists (Automated)
touch /var/log/sudo.log
chmod 600 /var/log/sudo.log
chown root:adm /var/log/sudo.log

# 5.3.1 Ensure permissions on /etc/ssh/sshd_config are configured (Automated)
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

# 5.3.2 Ensure permissions on SSH private host key files are configured (Automated)
chmod 600 /etc/ssh/ssh_host_rsa_key
chmod 600 /etc/ssh/ssh_host_ecdsa_key
chmod 600 /etc/ssh/ssh_host_ed25519_key
chown root:root /etc/ssh/ssh_host_rsa_key
chown root:root /etc/ssh/ssh_host_ecdsa_key
chown root:root /etc/ssh/ssh_host_ed25519_key

# 5.3.3 Ensure permissions on SSH public host key files are configured (Automated)
chmod 644 /etc/ssh/ssh_host_rsa_key.pub
chmod 644 /etc/ssh/ssh_host_ecdsa_key.pub
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub
chown root:root /etc/ssh/ssh_host_rsa_key.pub
chown root:root /etc/ssh/ssh_host_ecdsa_key.pub
chown root:root /etc/ssh/ssh_host_ed25519_key.pub

# 5.3.4 Ensure SSH access is limited (Automated)
echo "AllowUsers <username>" >> /etc/ssh/sshd_config
echo "AllowGroups <groupname>" >> /etc/ssh/sshd_config

# 5.3.5 Ensure SSH LogLevel is appropriate (Automated)
sed -i "s/^LogLevel.*/LogLevel VERBOSE/g" /etc/ssh/sshd_config

# 5.3.6 Ensure SSH X11 forwarding is disabled (Automated)
echo "X11Forwarding no" >> /etc/ssh/sshd_config

# 5.3.7 Ensure SSH MaxAuthTries is set to 4 or less (Automated)
sed -i "s/^MaxAuthTries.*/MaxAuthTries 4/g" /etc/ssh/sshd_config

# 5.3.8 Ensure SSH IgnoreRhosts is enabled (Automated)
sed -i "s/^IgnoreRhosts.*/IgnoreRhosts yes/g" /etc/ssh/sshd_config

#!/bin/bash

# 5.3.10 Ensure SSH root login is disabled
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config

# 5.3.11 Ensure SSH PermitEmptyPasswords is disabled
sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config

# 5.3.12 Ensure SSH PermitUserEnvironment is disabled
sed -i 's/#PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config

# 5.3.13 Ensure only strong Ciphers are used
sed -i 's/#Ciphers.*/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config

# 5.3.14 Ensure only strong MAC algorithms are used
sed -i 's/#MACs.*/MACs hmac-sha2-256,hmac-sha2-512/g' /etc/ssh/sshd_config

# 5.3.15 Ensure only strong Key Exchange algorithms are used
sed -i 's/#KexAlgorithms.*/KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256/g' /etc/ssh/sshd_config

# 5.3.16 Ensure SSH Idle Timeout Interval is configured
echo "ClientAliveInterval 900" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config

# 5.3.17 Ensure SSH LoginGraceTime is set to one minute or less
sed -i 's/LoginGraceTime.*/LoginGraceTime 1m/g' /etc/ssh/sshd_config

# 5.3.18 Ensure SSH warning banner is configured
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config

# 5.3.19 Ensure SSH PAM is enabled
sed -i 's/UsePAM no/UsePAM yes/g' /etc/ssh/sshd_config

# 5.3.20 Ensure SSH AllowTcpForwarding is disabled
sed -i 's/#AllowTcpForwarding.*/AllowTcpForwarding no/g' /etc/ssh/sshd_config

# 5.3.21 Ensure SSH MaxStartups is configured
sed -i 's/#MaxStartups.*/MaxStartups 10:30:60/g' /etc/ssh/sshd_config

# 5.3.22 Ensure SSH MaxSessions is limited
echo "MaxSessions 4" >> /etc/ssh/sshd_config

# 5.4.1 Ensure password creation requirements are configured
sed -i 's/# minlen.*/minlen 14/g' /etc/security/pwquality.conf
sed -i 's/# dcredit.*/dcredit -1/g' /etc/security/pwquality.conf
sed -i 's/# ucredit.*/ucredit -1/g' /etc/security/pwquality.conf
sed -i 's/# lcredit.*/lcredit -1/g' /etc/security/pwquality.conf
sed -i 's/# ocredit.*/ocredit -1/g' /etc/security/pwquality.conf


# 5.4.2 Ensure lockout for failed password attempts is configured
auth_file="/etc/pam.d/common-auth"
if grep -q "pam_tally2.so" $auth_file; then
    sed -i 's/auth required pam_tally2.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account/auth required pam_tally2.so deny=3 unlock_time=1800 onerr=fail audit even_deny_root_account/g' $auth_file
else
    echo "auth required pam_tally2.so deny=3 unlock_time=1800 onerr=fail audit even_deny_root_account" >> $auth_file
fi

# 5.4.3 Ensure password reuse is limited
auth_file="/etc/pam.d/common-password"
if grep -q "remember" $auth_file; then
    sed -i 's/^password .* remember=[0-9]*/password    required    pam_pwhistory.so remember=5/' $auth_file
else
    echo "password    required    pam_pwhistory.so remember=5" >> $auth_file
fi

# 5.4.4 Ensure password hashing algorithm is SHA-512
auth_file="/etc/login.defs"
if grep -q "^ENCRYPT_METHOD" $auth_file; then
    sed -i 's/^ENCRYPT_METHOD.*$/ENCRYPT_METHOD SHA512/' $auth_file
else
    echo "ENCRYPT_METHOD SHA512" >> $auth_file
fi

# 5.5.1.1 Ensure minimum days between password changes is configured
auth_file="/etc/login.defs"
if grep -q "^PASS_MIN_DAYS" $auth_file; then
    sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' $auth_file
else
    echo "PASS_MIN_DAYS 7" >> $auth_file
fi

# 5.5.1.2 Ensure password expiration is 365 days or less
auth_file="/etc/login.defs"
if grep -q "^PASS_MAX_DAYS" $auth_file; then
    sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 365/' $auth_file
else
    echo "PASS_MAX_DAYS 365" >> $auth_file
fi

# 5.5.1.3 Ensure password expiration warning days is 7 or more
auth_file="/etc/login.defs"
if grep -q "^PASS_WARN_AGE" $auth_file; then
    sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' $auth_file
else
    echo "PASS_WARN_AGE 7" >> $auth_file
fi

# 5.5.1.4 Ensure inactive password lock is 30 days or less
useradd_param="-f"
if [ "$(uname -m)" = "x86_64" ]; then
    useradd_param="-f30"
fi

useradd $useradd_param -D -f 30

# 5.5.1.5 Ensure all users last password change date is in the past
for user in $(awk -F: '($2!="*") {print $1}' /etc/shadow); do
    passwd -n 1 -u $user
done

#!/bin/bash

# 5.5.2 Ensure system accounts are secured (Automated)
awk -F: '($3 < 1000) {print $1 }' /etc/passwd >> /etc/security/hidden-users

# 5.5.3 Ensure default group for the root account is GID 0 (Automated)
sed -i 's/^.*:root:/root:/' /etc/passwd

# 5.5.4 Ensure default user umask is 027 or more restrictive (Automated)
echo "umask 027" >> /etc/bash.bashrc

# 5.5.5 Ensure default user shell timeout is 900 seconds or less (Automated)
echo "TMOUT=900" >> /etc/bash.bashrc

# 5.6 Ensure root login is restricted to system console (Manual)
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 5.7 Ensure access to the su command is restricted (Automated)
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

# 6.1.1 Audit system file permissions (Manual)
chmod -R g-wx,o-rwx /etc

# 6.1.2 Ensure permissions on /etc/passwd are configured (Automated)
chmod 644 /etc/passwd

# 6.1.3 Ensure permissions on /etc/passwd- are configured (Automated)
chmod 600 /etc/passwd-

# 6.1.4 Ensure permissions on /etc/group are configured (Automated)
chmod 644 /etc/group

# 6.1.5 Ensure permissions on /etc/group- are configured (Automated)
chmod 600 /etc/group-

# 6.1.6 Ensure permissions on /etc/shadow are configured (Automated)
chmod 000 /etc/shadow


# 6.1.7 Ensure permissions on /etc/shadow- are configured (Automated)
chmod o-rwx,g-rwx /etc/shadow-

# 6.1.8 Ensure permissions on /etc/gshadow are configured (Automated)
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

# 6.1.9 Ensure permissions on /etc/gshadow- are configured (Automated)
chmod o-rwx,g-rwx /etc/gshadow-

# 6.1.10 Ensure no world writable files exist (Automated)
find / -xdev -type f -perm -0002 -exec chmod o-w {} \;
find / -xdev -type d -perm -0002 -exec chmod o-w {} \;

# 6.1.11 Ensure no unowned files or directories exist (Automated)
find / -xdev -nouser -exec chown root:root {} \;

# 6.1.12 Ensure no ungrouped files or directories exist (Automated)
find / -xdev -nogroup -exec chown root:root {} \;

# 6.1.13 Audit SUID executables (Manual)
find / -xdev -type f -perm -4000

# 6.1.14 Audit SGID executables (Manual)
find / -xdev -type f -perm -2000

# 6.2.1 Ensure accounts in /etc/passwd use shadowed passwords (Automated)
pwck -r

# 6.2.2 Ensure password fields are not empty (Automated)
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow

# 6.2.3 Ensure all groups in /etc/passwd exist in /etc/group (Automated)
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:[^:]*:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
  fi
done


# 6.2.4 Ensure all users' home directories exist (Automated)
echo "Checking home directories..."
awk -F: '$5 == "" { print $1 }' /etc/passwd | while read -r user; do
    dir="$(eval echo ~$user)"
    if [ ! -d "$dir" ]; then
        echo "Creating home directory for $user..."
        mkdir -m 0700 "$dir"
        chown "$user:$user" "$dir"
    fi
done

# 6.2.5 Ensure users own their home directories (Automated)
echo "Checking home directory owners..."
for dir in $(grep -vE "^#" /etc/passwd | awk -F: '{ print $6 }'); do
    dirperm=$(ls -ld $dir | cut -f1 -d" ")
    if [ $(echo $dirperm | cut -c6) != "-" ]; then
        echo "Group owner for $dir is incorrect"
        chmod g-w $dir
    fi
    if [ $(echo $dirperm | cut -c9) != "-" ]; then
        echo "Other owner for $dir is incorrect"
        chmod o-w $dir
    fi
done

# 6.2.6 Ensure users' home directories permissions are 750 or more restrictive (Automated)
echo "Checking home directory permissions..."
for dir in $(grep -vE "^#" /etc/passwd | awk -F: '{ print $6 }'); do
    dirperm=$(ls -ld $dir | cut -f1 -d" ")
    if [ $(echo $dirperm | cut -c6-8) != "r-x------" ]; then
        echo "Permissions for $dir are incorrect"
        chmod 0700 $dir
    fi
done

# 6.2.7 Ensure users' dot files are not group or world writable (Automated)
echo "Checking user dot file permissions..."
for dir in $(grep -vE "^#" /etc/passwd | awk -F: '{ print $6 }'); do
    for file in $dir/.[A-Za-z0-9]*; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=$(ls -ld $file | cut -f1 -d" ")
            if [ $(echo $fileperm | cut -c6) != "-" ]; then
                echo "Group write permission set on file $file"
                chmod g-w $file
            fi
            if [ $(echo $fileperm | cut -c9) != "-" ]; then
                echo "Other write permission set on file $file"
                chmod o-w $file
            fi
        fi
    done
done

# 6.2.8 Ensure no users have .netrc files (Automated)
echo "Checking for .netrc files..."
for dir in $(grep -vE "^#" /etc/passwd | awk -F: '{ print $6 }'); do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".netrc file $file exists"
            rm -f $file
        fi
    done
done



#!/bin/bash

# 6.2.9 Ensure no users have .forward files
find /home -type f -name ".forward" -exec rm -f {} \;

# 6.2.10 Ensure no users have .rhosts files
find /home -type f -name ".rhosts" -exec rm -f {} \;

# 6.2.11 Ensure root is the only UID 0 account
sed -i '/^root:/!d' /etc/passwd
sed -i '/^root:/!d' /etc/shadow
sed -i '/^root:/!d' /etc/group

# 6.2.12 Ensure root PATH Integrity
echo 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"' > /root/.bashrc

# 6.2.13 Ensure no duplicate UIDs exist
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break ; set - $x ; if [ $1 -gt 1 ]; then users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`; echo "Duplicate UID ($2): ${users}"; fi ; done

# 6.2.14 Ensure no duplicate GIDs exist
awk -F: '{print $3}' /etc/group | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break ; set - $x ; if [ $1 -gt 1 ]; then groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`; echo "Duplicate GID ($2): ${groups}"; fi ; done

# 6.2.15 Ensure no duplicate user names exist
awk -F: '{print $1}' /etc/passwd | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break ; set - $x ; if [ $1 -gt 1 ]; then uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`; echo "Duplicate user name ($2): ${uids}"; fi ; done

# 6.2.16 Ensure no duplicate group names exist
awk -F: '{print $1}' /etc/group | sort -n | uniq -c | while read x ; do [ -z "${x}" ] && break ; set - $x ; if [ $1 -gt 1 ]; then gids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`; echo "Duplicate group name ($2): ${gids}"; fi ; done

# 6.2.17 Ensure shadow group is empty
if [ -z "$(grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group)" ]; then
  groupadd --system shadow
fi






