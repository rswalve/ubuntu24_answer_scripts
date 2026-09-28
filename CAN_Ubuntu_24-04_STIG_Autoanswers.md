################################################################################
DOCUMENT         : CAN_Ubuntu_24-04_STIG
VERSION          : 001.004.006
CHECKSUM         : e4528ded7de16ca234c0ed538dc6d78dc35f5678668cf9a6a40aa76f3954fe7f
MANUAL QUESTIONS : 16

IMPORTANT: Make sure to save the completed version of this file to: 
<SCC Install>/Resources/Content/Manual_Questions/Completed_Files

This file contains all of the non-automated STIG requirements found in the STIG.
Results from this file will be combined with automated checks in SCC to provide
complete STIG compliance results.

This file will be programmaticaly imported, so do not modify anything in this file
except for placing an '[X]' to select a Single answer, and entering text comments.

The list of questions is printed in order of severity, listing CAT I (High), then CAT II, etc..

################################################################################

QUESTION         : 1 of 16
APPLICABILITY    : LinuxGnome
TITLE            : CAT I, V-270711, SV-270711r1184069, SRG-OS-000480-GPOS-00227
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:13101
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:13101
RULE             : Ubuntu 24.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
QUESTION_TEXT    : Verify Ubuntu 24.04 LTS is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface with the following command:

$ gsettings get org.gnome.settings-daemon.plugins.media-keys logout
@as []

If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.

References:
CCI-000366
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 1 *******************************

QUESTION         : 2 of 16
TITLE            : CAT I, V-270748, SV-270748r1066733, SRG-OS-000134-GPOS-00068
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:20501
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:20501
RULE             : Ubuntu 24.04 LTS must ensure only users who need access to security functions are part of sudo group.
QUESTION_TEXT    : Verify the sudo group has only members who require access to security functions with the following command:  
 
$ grep sudo /etc/group
sudo:x:27:foo 
 
If the sudo group contains users not needing access to security functions, this is a finding.

References:
CCI-001084
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 2 *******************************

QUESTION         : 3 of 16
TITLE            : CAT I, V-279938, SV-279938r1156367, SRG-OS-000095-GPOS-00049
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:38701
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:38701
RULE             : Ubuntu 24.04 LTS must not have the nfs-kernel-server package installed.
QUESTION_TEXT    : Verify Ubuntu 24.04 LTS does not have nfs packages installed.

Check if packages are installed:
$sudo dpkg -l | grep -E 'nfs-common | nfs-kernel-server'

If the nfs-common or nfs-kernel-server packages are installed, this is a finding

References:
CCI-000381
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 3 *******************************

QUESTION         : 4 of 16
TITLE            : CAT II, V-270650, SV-270650r1155241, SRG-OS-000445-GPOS-00199
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:1101
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:1101
RULE             : Ubuntu 24.04 LTS must configure AIDE to perform file integrity checking on the file system if installed.
QUESTION_TEXT    : Note: If a file integrity tool other than Advanced Intrusion Detection Environment (AIDE) is employed, this requirement is not applicable.

Verify AIDE is configured on the system by performing a manual check:

$ sudo aide -c /etc/aide/aide.conf --check

Example output:
...
Start timestamp: 2024-10-30 14:22:38 -0400 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!
...

If AIDE is being used for system file integrity checking and the command fails, this is a finding.

References:
CCI-002696
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 4 *******************************

QUESTION         : 5 of 16
TITLE            : CAT II, V-270651, SV-270651r1068395, SRG-OS-000446-GPOS-00200
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:1301
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:1301
RULE             : Ubuntu 24.04 LTS must be configured so that the script which runs each 30 days or less to check file integrity is the default one.
QUESTION_TEXT    : Note: If AIDE is not installed, this finding is not applicable.

Check the AIDE configuration file integrity installed on the system (the default configuration file is located at /etc/aide/aide.conf or in /etc/aide/aide.conf.d/) with the following command:
$ sudo sha256sum /etc/aide/aide.conf
f3bbea2552f2c5b475627850d8a5fba1659df6466986d5a18948d9821ecbe491  /etc/aide/aide.conf

Download the original aide-common package in the /tmp directory: 
$ cd /tmp; apt download aide-common 

Generate the checksum from the aide.conf file in the downloaded .deb package:
$ sudo dpkg-deb --fsys-tarfile /tmp/aide-common_0.18.6-2build2_all.deb | tar -xO ./usr/share/aide/config/aide/aide.conf | sha256sum
f3bbea2552f2c5b475627850d8a5fba1659df6466986d5a18948d9821ecbe491  -

If the checksums of the system file (/etc/aide/aide.conf) and the extracted file do not match, this is a finding.

To verify the frequency of the file integrity checks, inspect the contents of the scheduled jobs as follows:

Checking scheduled cron jobs:
$ grep -r aide /etc/cron* /etc/crontab
/etc/cron.daily/dailyaidecheck:SCRIPT="/usr/share/aide/bin/dailyaidecheck"

Checking the systemd timer (this will show when the next scheduled run occurs and the last time the AIDE check was triggered):
$ sudo systemctl list-timers | grep aide
Thu 2024-10-31 02:01:58 EDT           10h Wed 2024-10-30 13:47:41 EDT            - dailyaidecheck.timer           dailyaidecheck.service

The contents of these files can be inspected with the following commands:
$ sudo systemctl cat dailyaidecheck.timer
$ sudo systemctl cat dailyaidecheck.service

If there is no AIDE script file in the cron directories or in the systemd timer, this is a finding.

References:
CCI-002699
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 5 *******************************

QUESTION         : 6 of 16
TITLE            : CAT II, V-270679, SV-270679r1107295, SRG-OS-000028-GPOS-00009
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:6901
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:6901
RULE             : Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user interface automount function.
QUESTION_TEXT    : Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify Ubuntu 24.04 LTS disables the ability of the user to override the graphical user interface automount setting.

Determine which profile the system database is using with the following command:

$ sudo grep system-db /etc/dconf/profile/user

system-db:local

Check that the automount setting is locked from nonprivileged user modification with the following command:

Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.

$ grep 'automount-open' /etc/dconf/db/local.d/locks/* 

/org/gnome/desktop/media-handling/automount-open

If the command does not return at least the example result, this is a finding.

References:
CCI-000056
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 6 *******************************

QUESTION         : 7 of 16
TITLE            : CAT II, V-270682, SV-270682r1066535, SRG-OS-000002-GPOS-00002
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:7501
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:7501
RULE             : Ubuntu 24.04 LTS must automatically remove or disable emergency accounts after 72 hours.
QUESTION_TEXT    : Verify temporary accounts have been provisioned with an expiration date of 72 hours with the following command:

$ sudo chage -l <temporary_account_name> | grep -i "account expires"

Verify each of these accounts has an expiration date set within 72 hours.

If any temporary accounts have no expiration date set or do not expire within 72 hours, this is a finding.

References:
CCI-000016
CCI-001682
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 7 *******************************

QUESTION         : 8 of 16
TITLE            : CAT II, V-270719, SV-270719r1067172, SRG-OS-000096-GPOS-00050
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:14701
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:14701
RULE             : Ubuntu 24.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL) and vulnerability assessments.
QUESTION_TEXT    : Check the firewall configuration for any unnecessary or prohibited functions, ports, protocols, and/or services with the following command:
 
$ sudo ufw show raw 
Chain OUTPUT (policy ACCEPT) 
target  prot opt sources    destination 
Chain INPUT (policy ACCEPT 1 packets, 40 bytes) 
    pkts      bytes target     prot opt in     out     source               destination 
 
Chain FORWARD (policy ACCEPT 0 packets, 0 bytes) 
    pkts      bytes target     prot opt in     out     source               destination 
 
Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes) 
    pkts      bytes target     prot opt in     out     source               destination 
 
Ask the system administrator for the site or program PPSM Components Local Services Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA.  
 
If there are any additional ports, protocols, or services that are not included in the PPSM CLSA, this is a finding. 
 
If there are any ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.

References:
CCI-000382
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : PPSM was generated using the Ports, Protocols, and Services of our EC2 instances

******************************* end of question 8 *******************************

QUESTION         : 9 of 16
TITLE            : CAT II, V-270735, SV-270735r1066694, SRG-OS-000066-GPOS-00034
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:17901
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:17901
RULE             : Ubuntu 24.04 LTS, for PKI-based authentication, SSSD must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
QUESTION_TEXT    : Verify Ubuntu 24.04 LTS, for PKI-based authentication, has valid certificates by constructing a certification path to an accepted trust anchor. 

Ensure the pam service is listed under [sssd] with the following command:

$ sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf
[sssd]
services = nss,pam,ssh

If "pam" is not listed in services, this is a finding.

Additionally, ensure the pam service is set to use pam for smart card authentication in the [pam] section of /etc/sssd/sssd.conf with the following command:

$ sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf
[pam]
pam_cert_auth = True

If "pam_cert_auth = True" is not returned, this is a finding.

Ensure "ca" is enabled in "certificate_verification" with the following command: 
  
$ sudo grep certificate_verification /etc/sssd/sssd.conf
certificate_verification = ca_cert,ocsp
 
If "certificate_verification" is not set to "ca" or the line is commented out, this is a finding.

References:
CCI-000185
CCI-004909
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 9 *******************************

QUESTION         : 10 of 16
TITLE            : CAT II, V-270745, SV-270745r1066724, SRG-OS-000403-GPOS-00182
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:19901
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:19901
RULE             : Ubuntu 24.04 LTS must use DOD PKI-established certificate authorities (CAs) for verification of the establishment of protected sessions.
QUESTION_TEXT    : Verify the directory containing the root certificates for Ubuntu 24.04 LTS contains certificate files for DOD PKI-established CAs by iterating over all files in the "/etc/ssl/certs" directory and checking if, at least one, has the subject matching "DOD ROOT CA".

$ grep -ir DOD /etc/ssl/certs
DOD_PKE_CA_chain.pem

If no root certificate is found, this is a finding.

References:
CCI-002470
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 10 *******************************

QUESTION         : 11 of 16
TITLE            : CAT II, V-270747, SV-270747r1066730, SRG-OS-000185-GPOS-00079
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:20301
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:20301
RULE             : Ubuntu 24.04 LTS handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
QUESTION_TEXT    : Note: If there is a documented and approved mission requirement for data-at-rest to not be encrypted, this requirement is not applicable. 
 
Verify Ubuntu 24.04 LTS prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption.  

Determine the partition layout for the system with the following command: 
 
$ sudo fdisk -l 
(..) 
Disk /dev/vda: 15 GiB, 16106127360 bytes, 31457280 sectors 
Units: sectors of 1 * 512 = 512 bytes 
Sector size (logical/physical): 512 bytes / 512 bytes 
I/O size (minimum/optimal): 512 bytes / 512 bytes 
Disklabel type: gpt 
Disk identifier: 83298450-B4E3-4B19-A9E4-7DF147A5FEFB 
 
Device       Start      End  Sectors Size Type 
/dev/vda1     2048     4095     2048   1M BIOS boot 
/dev/vda2     4096  2101247  2097152   1G Linux filesystem 
/dev/vda3  2101248 31455231 29353984  14G Linux filesystem 
(...) 
 
Verify the system partitions are all encrypted with the following command: 
 
$ more /etc/crypttab
 
Every persistent disk partition present must have an entry in the file.  
 
If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not listed, this is a finding.

References:
CCI-001199
CCI-002475
CCI-002476
CCI-004910
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [ ] Not a Finding
     [X] Not Applicable
     [ ] Not Reviewed
     Enter any comments : Data-at-rest protection is provided by AWS EBS encryption using an AWS KMS Key. Operating-system level LUKS encryption is not implemented on the root volume due to operational constraints of the EC2 environment

******************************* end of question 11 *******************************

QUESTION         : 12 of 16
TITLE            : CAT II, V-274871, SV-274871r1107302, SRG-OS-000031-GPOS-00012
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:37901
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:37901
RULE             : Ubuntu 24.04 LTS must conceal, via the session lock, information previously visible on the display with a publicly viewable image.
QUESTION_TEXT    : Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

To verify the screensaver is configured to be blank, run the following command:

$ gsettings writable org.gnome.desktop.screensaver picture-uri
 
false
 
If "picture-uri" is writable and the result is "true", this is a finding.

References:
CCI-000060
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 12 *******************************

QUESTION         : 13 of 16
TITLE            : CAT II, V-274873, SV-274873r1107300, SRG-OS-000028-GPOS-00009
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:38301
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:38301
RULE             : Ubuntu 24.04 LTS must prevent a user from overriding the disabling of the graphical user smart card removal action.
QUESTION_TEXT    : Note: This requirement assumes the use of the Ubuntu 24.04 LTS default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify Ubuntu 24.04 LTS disables the ability of the user to override the smart card removal action setting.

$ gsettings writable org.gnome.settings-daemon.peripherals.smartcard removal-action
 
false
 
If "removal-action" is writable and the result is "true", this is a finding.

References:
CCI-000056
CCI-000057
CCI-000058
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [ ] Finding
     [X] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 13 *******************************

QUESTION         : 14 of 16
TITLE            : CAT III, V-270817, SV-270817r1066940, SRG-OS-000479-GPOS-00224
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:34101
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:34101
RULE             : Ubuntu 24.04 LTS must have a crontab script running weekly to offload audit events of standalone systems.
QUESTION_TEXT    : Note: If this is an interconnected system, this is not applicable.
 
Verify there is a script that offloads audit data and that script runs weekly with the following command:

$ ls /etc/cron.weekly 
audit-offload 
 
Check if the script inside the file offloads audit logs to external media. 
 
If the script file does not exist or does not offload audit logs, this is a finding.

References:
CCI-001851
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [X] Finding
     [ ] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 14 *******************************

QUESTION         : 15 of 16
TITLE            : CAT III, V-270818, SV-270818r1066943, SRG-OS-000343-GPOS-00134
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:34301
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:34301
RULE             : Ubuntu 24.04 LTS must immediately notify the system administrator (SA) and information system security officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.
QUESTION_TEXT    : Verify Ubuntu 24.04 LTS notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity with the following command: 
 
Note: If the space_left_action is set to "email", an email package must be available.

$ sudo grep ^space_left_action /etc/audit/auditd.conf
space_left_action email 
 
$ sudo grep ^space_left /etc/audit/auditd.conf
space_left 250000 
 
If the "space_left" parameter is set to "syslog", is missing, set to blanks, or set to a value less than 25 percent of the space free in the allocated audit record storage, this is a finding. 
 
If the "space_left_action" parameter is missing or set to blanks, this is a finding. 

If the "space_left_action" is set to "email", check the value of the "action_mail_acct" parameter with the following command: 
 
$ sudo grep ^action_mail_acct /etc/audit/auditd.conf
action_mail_acct root@localhost 
 
The "action_mail_acct" parameter, if missing, defaults to "root". If the "action_mail_acct parameter" is not set to the email address of the SA(s) and/or ISSO, this is a finding.   
 
If the "space_left_action" is set to "exec", the system executes a designated script. If this script informs the SA of the event, this is not a finding. 

References:
CCI-001855
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [X] Finding
     [ ] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 15 *******************************

QUESTION         : 16 of 16
TITLE            : CAT III, V-270819, SV-270819r1068390, SRG-OS-000046-GPOS-00022
TEST_ACTION_ID   : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:testaction:34501
QUESTION_ID      : ocil:navy.navwar.niwcatlantic.scc.ubuntu2404os:question:34501
RULE             : Ubuntu 24.04 LTS must alert the system administrator (SA) and information system security officer (ISSO) (at a minimum) in the event of an audit processing failure.
QUESTION_TEXT    : Verify that the SA and ISSO (at a minimum) are notified in the event of an audit processing failure with the following command: 
 
$ sudo grep '^action_mail_acct' /etc/audit/auditd.conf
action_mail_acct = <administrator_account> 
 
If the value of the "action_mail_acct" keyword is not set to an account for security personnel, the returned line is commented out, or the keyword is missing, this is a finding.

References:
CCI-000139
     ===========================================================================
     Select One of the following by entering an X in the brackets
     [X] Finding
     [ ] Not a Finding
     [ ] Not Applicable
     [ ] Not Reviewed
     Enter any comments : 

******************************* end of question 16 *******************************

