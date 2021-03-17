# Microsoft Defender 365 raw data schema - Overview

## Last changes:
| Date | Description |
| :--- | :--- |
| **16.03.2020** | Finished 1.0

## List of possible services and detections:
| Abbreviation  | ServiceSource | DetectionSource
| :--- | :--- | :--- |
| **MDE** | Microsoft Defender for Endpoint | Antivirus, Automated investigation, Custom TI, EDR, SmartScreen, Microsoft Threat Experts |
| **MDI** | Microsoft Defender for Identity | Microsoft Defender for Identity
| **MDO** | Microsoft Defender for Office 365 | Microsoft Defender for Office 365
| **MCAS** | Microsoft Cloud App Security | Cloud App Security
| **M365D** | Microsoft 365 Defender | all

Schema Overview
=================
  * [Alerts](#alerts)
    * [Table: AlertInfo](#alertinfo)
      * [Alerts by severity](#alerts-by-severity)
      * [Alerts by MITRE ATT&CK technique](#alerts-by-mitre-attck-technique)
    * [Table: AlertEvidence](#alertevidence)
      * [Alerts on a device](#alerts-on-a-device)
      * [Alerts involving a user](#alerts-involving-a-user)
  * [Apps & identities](#apps--identities)
    * [Table: IdentityInfo](#identityinfo)
      * [Users in a country](#users-in-a-country)
      * [Users in a department](#users-in-a-department)
    * [Table: IdentityLogonEvents](#identitylogonevents)
      * [IdentityLogonEvents ActionTypes](#identitylogonevents-actiontypes)
      * [Cleartext passwords in LDAP authentication](#cleartext-passwords-in-ldap-authentication)
    * [Table: IdentityQueryEvents](#identityqueryevents)
      * [IdentityQueryEvents ActionTypes](#identityqueryevents-actiontypes)
      * [Active Directory SAMR queries using net.exe](#active-directory-samr-queries-using-netexe)
    * [Table: IdentityDirectoryEvents](#identitydirectoryevents)
      * [IdentityDirectoryEvents ActionTypes](#identitydirectoryevents-actiontypes)
      * [Group modifications](#group-modifications)
      * [Last password update](#last-password-update)
    * [Table: AppFileEvents](#appfileevents)
      * [AppFileEvents ActionTypes](#appfileevents-actiontypes)
      * [File activity over time](#file-activity-over-time)
      * [File name extension change](#file-name-extension-change)
    * [Table: CloudAppEvents](#cloudappevents)
      * [CloudAppEvents ActionTypes](#cloudappevents-actiontypes)
    * [Table: AADSpnSignInEventsBeta](#aadspnsignineventsbeta)
      * [Most active managed identities](#most-active-managed-identities)
      * [Inactive service principals](#inactive-service-principals)
    * [Table: AADSignInEventsBeta](#aadsignineventsbeta)
      * [Sign-ins to disabled accounts](#sign-ins-to-disabled-accounts)
      * [User signing in from multiple locations](#user-signing-in-from-multiple-locations)
  * [Email](#email)
    * [Table: EmailEvents](#emailevents)
      * [Phishing emails from the top ten sender domains](#phishing-emails-from-the-top-ten-sender-domains)
      * [Emails with malware](#emails-with-malware)
    * [Table: EmailAttachmentInfo](#emailattachmentinfo)
      * [Files from malicious sender](#files-from-malicious-sender)
      * [Emails to external domains with attachments](#emails-to-external-domains-with-attachments)
    * [Table: EmailUrlInfo](#emailurlinfo)
      * [URLs in an email](#urls-in-an-email)
    * [Table: EmailPostDeliveryEvents](#emailpostdeliveryevents)
      * [Post-delivery administrator actions](#post-delivery-administrator-actions)
      * [Unremediated post-delivery phishing email detections](#unremediated-post-delivery-phishing-email-detections)
      * [Full email process details](#full-email-process-details)
  * [Threat & Vulnerability Management](#threat--vulnerability-management)
    * [Table: DeviceTvmSoftwareInventoryVulnerabilities](#devicetvmsoftwareinventoryvulnerabilities)
    * [Table: DeviceTvmSoftwareVulnerabilitiesKB](#devicetvmsoftwarevulnerabilitieskb)
    * [Table: DeviceTvmSecureConfigurationAssessment](#devicetvmsecureconfigurationassessment)
    * [Table: DeviceTvmSecureConfigurationAssessmentKB](#devicetvmsecureconfigurationassessmentkb)
  * [Devices](#devices)
    * [Table: DeviceInfo](#deviceinfo)
      * [Devices with outdated operating systems](#devices-with-outdated-operating-systems)
      * [Logged on users](#logged-on-users)
    * [Table: DeviceNetworkInfo](#devicenetworkinfo)
      * [Devices with a specific IP address](#devices-with-a-specific-ip-address)
    * [Table: DeviceProcessEvents](#deviceprocessEvents)
      * [DeviceProcessEvents ActionTypes](#deviceprocessevents-actiontypes)
      * [Clearing of event logs](#clearing-of-event-logs)
      * [PowerShell activity triggered by malicious email](#powerShell-activity-triggered-by-malicious-email)
    * [Table: DeviceNetworkEvents](#devicenetworkevents)
      * [DeviceNetworkEvents ActionTypes](#devicenetworkevents-actiontypes)
      * [Tor client connections](#tor-client-connections)
      * [PowerShell download activity](#powerShell-download-activity)
    * [Table: DeviceFileEvents](#devicefileevents)
      * [DeviceFileEvents ActionTypes](#devicefileevents-actiontypes)
      * [Sensitive file uploads](#sensitive-file-uploads)
      * [Copy or move file](#copy-or-move-file)
    * [Table: DeviceRegistryEvents](#deviceregistryevents)
      * [DeviceRegistryEvents ActionTypes](#deviceregistryevents-actiontypes)
      * [Devices with security controls turned off](#devices-with-security-controls-turned-off)
      * [Autostart services](#autostart-services)
    * [Table: DeviceLogonEvents](#devicelogonevents)
      * [DeviceLogonEvents ActionTypes](#devicelogonevents-actiontypes)
      * [Admin logons](#admin-logons)
      * [Logons after receipt of malicious emails](#logons-after-receipt-of-malicious-emails)
    * [Table: DeviceImageLoadEvents](#deviceimageloadevents)
      * [DeviceImageLoadEvents ActionTypes](#deviceimageloadevents-actiontypes)
    * [Table: DeviceEvents](#deviceevents)
      * [DeviceEvents ActionTypes](#deviceevents-actiontypes)
      * [USB devices](#usb-devices)
      * [Antivirus scan events](#antivirus-scan-events)
    * [Table: DeviceFileCertificateInfo](#devicefilecertificateinfo)
      * [Files with spoofed Microsoft certificates](#files-with-spoofed-microsoft-certificates)

# Alerts

## AlertInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-alertinfo-table?view=o365-worldwide)
**Description:** Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization.
The AlertInfo table in the advanced hunting schema contains information about alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the event was recorded |
| **AlertId** | Unique identifier for the alert
| **Title** | Title of the alert
| **Category** | Type of threat indicator or breach activity identified by the alert
| **Severity** | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert
| **ServiceSource** | Product or service that provided the alert information
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the alert

### Examples:

#### Alerts by severity
```
AlertInfo
| summarize alertsCount=dcount(AlertId) by Severity
| sort by alertsCount desc
```

#### Alerts by MITRE ATT&CK technique
```
AlertInfo
| where isnotempty(AttackTechniques)
| mvexpand todynamic(AttackTechniques) to typeof(string)
| summarize AlertCount = dcount(AlertId) by AttackTechniques
| sort by AlertCount desc
```

## AlertEvidence
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-alertevidence-table?view=o365-worldwide)
**Description:** Files, IP addresses, URLs, users, or devices associated with alerts. The AlertEvidence table in the advanced hunting schema contains information about various entities-files, IP addresses, URLs, users, or devices—associated with alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the event was recorded
| **AlertId** | Unique identifier for the alert
| **ServiceSource** | Product or service that provided the alert information
| **EntityType** | Type of object, such as a file, a process, a device, or a user
| **EvidenceRole** | How the entity is involved in an alert, indicating whether it is impacted or is merely related
| **EvidenceDirection** | Indicates whether the entity is the source or the destination of a network connection
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **SHA1** | SHA-1 of the file that the recorded action was applied to
| **SHA256** | SHA-256 of the file that the recorded action was applied to. This field is usually not populated—use the SHA1 column when available.
| **FileSize** | Size of the file in bytes
| **ThreatFamily** | Malware family that the suspicious or malicious file or process has been classified under
| **RemoteIP** | IP address that was being connected to
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountObjectId** | Unique identifier for the account in Azure Active Directory
| **AccountUpn** | User principal name (UPN) of the account
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the machine
| **LocalIP** | IP address assigned to the local device used during communication
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365
| **EmailSubject** | Subject of the email
| **ApplicationId** | Unique identifier for the application
| **Application** | Application that performed the recorded action
| **ProcessCommandLine** | Command line used to create the new process
| **AdditionalFields** | Additional information about the event in JSON array format
| **RegistryKey** | Registry key that the recorded action was applied to
| **RegistryValueName** | Name of the registry value that the recorded action was applied to
| **RegistryValueData** | Data of the registry value that the recorded action was applied to

### Examples:

#### Alerts on a device:
```
let myDevice = "<insert your device ID>";
let deviceName = "<insert your device name>";
AlertEvidence
| extend DeviceName = todynamic(AdditionalFields)["HostName"]
| where EntityType == "Machine" and (DeviceId == deviceId or DeviceName == myDevice)
| project DeviceId, DeviceName, AlertId
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, DeviceId, DeviceName
```

#### Alerts involving a user:
```
let userID = "<inert your AAD user ID>";
let userSid = "<inert your user SID>";
AlertEvidence
| where EntityType == "User" and (AccountObjectId == userID or AccountSid == userSid )
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, AccountObjectId, AccountName, AccountDomain , AccountSid
```

# Apps & identities

## IdentityInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-identityinfo-table?view=o365-worldwide)
**Description:** Account information from various sources, including Azure Active Directory. The IdentityInfo table in the advanced hunting schema contains information about user accounts obtained from various services, including Azure Active Directory. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountUpn** | User principal name (UPN) of the account
| **OnPremSid** | On-premises security identifier (SID) of the account
| **CloudSid** | Cloud security identifier of the account
| **GivenName** | Given name or first name of the account user
| **Surname** | Surname, family name, or last name of the account user
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **Department** | Name of the department that the account user belongs to
| **JobTitle** | Job title of the account user
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **EmailAddress** | SMTP address of the account
| **SipProxyAddress** | Voice of over IP (VOIP) session initiation protocol (SIP) address of the account
| **City** | City where the client IP address is geolocated
| **Country** | Country/Region where the account user is located
| **IsAccountEnabled** | Indicates whether the account is enabled or not

### Examples:

#### Users in a country:
```
let MyCountry= "<insert your contry>";
IdentityInfo
| where Country  == MyCountry
| summarize by AccountObjectId, AccountUpn
```

#### Users in a department:
```
let MyDepartment= "<insert your department>";
IdentityInfo
| where Department == MyDepartment
| summarize by AccountObjectId, AccountUpn
```

## IdentityLogonEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-identitylogonevents-table?view=o365-worldwide)
**Description:** Authentication events recorded by Active Directory and other Microsoft online services. The IdentityLogonEvents table in the advanced hunting schema contains information about authentication activities made through your on-premises Active Directory captured by Microsoft Defender for Identity and authentication activities related to Microsoft online services captured by Microsoft Cloud App Security. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **ActionType** | Type of activity that triggered the event
| **Application** | Application that performed the recorded action
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service
| **Protocol** | Protocol used during the communication
| **FailureReason** | Information explaining why the recorded action failed
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **AccountUpn** | User principal name (UPN) of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **DeviceType** | Type of the device
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7
| **IPAddress** | IP address assigned to the device during communication
| **Port** | TCP port used during communication
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action
| **DestinationPort** | Destination port of the activity
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to
| **Location** | City, country, or other geographic location associated with the event
| **ISP** | Internet service provider associated with the IP address
| **ReportId** | Unique identifier for the event
| **AdditionalFields** | Additional information about the entity or event

### IdentityLogonEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **LogonSuccess** | A user successfully logged on to the device.
| **LogonFailed** | A user attempted to logon to the device but failed.

### Examples

#### Cleartext passwords in LDAP authentication:
```
// Find processes that performed LDAP authentication with cleartext passwords
IdentityLogonEvents
| where Timestamp > ago(7d)
| where Protocol == "LDAP" //and isnotempty(AccountName)
| project LogonTime = Timestamp, DeviceName, Application, ActionType, LogonType //,AccountName
| join kind=inner (
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| extend DeviceName = toupper(trim(@"\..*$",DeviceName))
| where RemotePort == "389"
| project NetworkConnectionTime = Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
) on DeviceName
| where LogonTime - NetworkConnectionTime between (-2m .. 2m)
| project Application, LogonType, ActionType, LogonTime, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine //, AccountName
```

## IdentityQueryEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-identityqueryevents-table?view=o365-worldwide)
**Description:** Query activities performed against Active Directory objects, such as users, groups, devices, and domain. The IdentityQueryEvents table in the advanced hunting schema contains information about queries performed against Active Directory objects, such as users, groups, devices, and domains. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **ActionType** | Type of activity that triggered the event
| **Application** | Application that performed the recorded action
| **QueryType** | Type of the query
| **QueryTarget** | User, group, domain, or any other entity being queried
| **Query** | String used to run the query
| **Protocol** | Protocol used during the communication
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **AccountUpn** | User principal name (UPN) of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **IPAddress** | IP address assigned to the device during communication
| **Port** | TCP port used during communication
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action
| **DestinationPort** | Destination port of the activity
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to
| **Location** | City, country, or other geographic location associated with the event
| **ReportId** | Unique identifier for the event
| **AdditionalFields** | Additional information about the entity or event

### IdentityQueryEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **LDAP query** | An LDAP query was performed.
| **DNS query** | Type of query user performed against the domain controller (AXFR, TXT, MX, NS, SRV, ANY, DNSKEY)
| **SAMR query** | A SAMR query was performed.

### Examples:

#### Active Directory SAMR queries using net.exe:
```
// Find processes that sent SAMR queries to Active Directory
IdentityQueryEvents
| where Timestamp > ago(3d)
| where ActionType == "SAMR query"
//    and isnotempty(AccountName)
| project QueryTime = Timestamp, DeviceName, AccountName, Query, QueryTarget
| join kind=inner (
DeviceProcessEvents
| where Timestamp > ago(3d)
| extend DeviceName = toupper(trim(@"\..*$",DeviceName))
//| where InitiatingProcessCommandLine contains "net.exe"
| project ProcessCreationTime = Timestamp, DeviceName, AccountName,
     InitiatingProcessFileName , InitiatingProcessCommandLine
    ) on DeviceName//, AccountName
| where ProcessCreationTime - QueryTime between (-2m .. 2m)
| project QueryTime, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, Query, QueryTarget //,AccountName
```

## IdentityDirectoryEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide)
**Description:** Events involving a domain controller or a directory service, such as Active Directory (AD ) or Azure AD. The IdentityDirectoryEvents table in the advanced hunting schema contains events involving an on-premises domain controller running Active Directory (AD). This table captures various identity-related events, like password changes, password expiration, and user principal name (UPN) changes. It also captures system events on the domain controller, like scheduling of tasks and PowerShell activity. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **ActionType** | Type of activity that triggered the event
| **Application** | Application that performed the recorded action
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action
| **DestinationPort** | Destination port of the activity
| **Protocol** | Protocol used during the communication
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **AccountUpn** | User principal name (UPN) of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **IPAddress** | IP address assigned to the device during communication
| **Port** | TCP port used during communication
| **Location** | City, country, or other geographic location associated with the event
| **ISP** | Internet service provider associated with the IP address
| **ReportId** | Unique identifier for the event
| **AdditionalFields** | Additional information about the entity or event

### IdentityDirectoryEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **Account Constrained Delegation State changed** | The account state is now enabled or disabled for delegation.
| **Account Constrained Delegation SPNs changed** | Constrained delegation restricts the services to which the specified server can act on behalf of the user.
| **Account Delegation changed** | The account state is now enabled or disabled for delegation.
| **Account Disabled changed** | Indicates whether an account is disabled or enabled.
| **Account Display Name changed** | User's display name was changed.
| **Account expired** | Date when the account expires.
| **Account Expiry Time changed** | Change to the date when the account expires.
| **Account Locked changed** | Change to the date when the account expires.
| **Account Name changed** | User's name was changed.
| **Account Password changed** | User changed their password.
| **Account Password expired** | User's password expired.
| **Account Password Never Expires changed** | User's password changed to never expire.
| **Account Password Not Required changed** | User account was changed allow logging in with a blank password.
| **Account Path changed** | User Distinguished name was changed from X to Y.
| **Account Smartcard Required changed** |
| **Account Supported Encryption Types changed** | Kerberos supported encryption types were changed(types: Des, AES 129, AES 256).
| **Account Upn Name changed** | User's principle name was changed.
| **Directory Service replication** | User tried to replicate the directory service.
| **Group Membership changed** | User was added/removed, to/from a group, by another user or by themselves.
| **Potential lateral movement path identified** | Identified potential lateral movement path to a sensitive user.
| **PowerShell execution** | User attempted to remotely execute a PowerShell command.
| **Private Data retrieval** | -
| **Security Principal created** | Account was created (both user and computer).
| **Security Principal deleted changed** | Account was deleted/restored (both user and computer).
| **Security Principal Display Name changed** | Account display name was changed from X to Y.
| **Security Principal Name changed** | Account name attribute was changed.
| **Security Principal Path changed** | Account Distinguished name was changed from X to Y.
| **Security Principal Sam Name changed** | SAM name changed (SAM is the logon name used to support clients and servers running earlier versions of the operating system).
| **Service creation** | User attempted to remotely create a specific service to a remote machine.
| **SMB session** | User attempted to enumerate all users with open SMB sessions on the domain controllers.
| **Task scheduling** | User tried to remotely schedule X task to a remote machine.
| **User Mail changed** | Users email attribute was changed.
| **User Manager changed** | User's manager attribute was changed.
| **User Phone Number changed** | User's phone number attribute was changed.
| **User Title changed** | User's title attribute was changed.
| **Wmi execution** | User attempted to remotely execute a WMI method.

### Examples:

#### Group modifications:
```
let group = '<insert your group>';
IdentityDirectoryEvents
| where ActionType == 'Group Membership changed'
| extend AddedToGroup = AdditionalFields['TO.GROUP']
| extend RemovedFromGroup = AdditionalFields['FROM.GROUP']
| extend TargetAccount = AdditionalFields['TARGET_OBJECT.USER']
| where AddedToGroup == group or RemovedFromGroup == group
| project-reorder Timestamp, ActionType, AddedToGroup, RemovedFromGroup, TargetAccount
| limit 100
```

#### Last password update:
```
//Find the latest password change event for a specific account
let userAccount = '<insert your user account>';
let deviceAccount = 'insert your device account';
IdentityDirectoryEvents
| where ActionType == 'Account Password changed'
| where TargetAccountDisplayName == userAccount
//If you are looking for last password change of a device account comment the above row and remove comment from the below row
//| where TargetDeviceName == deviceAccount
| summarize LastPasswordChangeTime = max(Timestamp) by TargetAccountDisplayName // or change to TargetDeviceName for devcie account
```

## AppFileEvents
**Retired March 7, 2021 and replaced by [Table: CloudAppEvents](#cloudappevents)**

[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-appfileevents-table?view=o365-worldwide)
**Description:** File-related activities in cloud apps and services. The AppFileEvents table in the advanced hunting schema contains information about file-related activities in cloud apps and services monitored by Microsoft Cloud App Security. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **ActionType** | Type of activity that triggered the event
| **Application** | Application that performed the recorded action
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **PreviousFileName** | Original name of the file that was renamed as a result of the action
| **PreviousFolderPath** | Original folder containing the file before the recorded action was applied
| **Protocol** | Protocol used during the communication
| **AccountName** | User name of the account
| **AccountDomain** | Domain of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountUpn** | User principal name (UPN) of the account
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **DeviceType** | Type of the device
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7
| **IPAddress** | IP address assigned to the device during communication
| **Port** | TCP port used during communication
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action
| **DestinationPort** | Destination port of the activity
| **Location** | City, country, or other geographic location associated with the event
| **ISP** | Internet service provider associated with the IP address
| **ReportId** | Unique identifier for the event
| **AdditionalFields** | Additional information about the entity or event

### AppFileEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **FileUploaded** | A file was uploaded to a cloud app or service.
| **FileDownloaded** | A file in a cloud app or service was downloaded.
| **FileAccessed** | A file in a cloud app or service was accessed.
| **FileMoved** | A file in a cloud app or service was moved.
| **SmbFileCopy** | User copied files using SMB.

### Examples:

#### File activity over time:
```
let MyFileName = "<insert your File Name>";
AppFileEvents
| union DeviceFileEvents
| where FileName == MyFileName
| summarize FileCount = count() by bin(Timestamp, 30m)
| render linechart
```

#### File name extension change:
```
// Find applications that renamed .docx files to .doc on devices
AppFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileRenamed"
| join kind=inner (
DeviceFileEvents
| where Timestamp > ago(7d)
| project FileName, AccountName = InitiatingProcessAccountName, DeviceName
) on FileName, AccountName
| where FileName endswith "doc" and PreviousFileName endswith "docx"
| project Timestamp, FileName, PreviousFileName, Application, AccountName, DeviceName
```

## CloudAppEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-cloudappevents-table?view=o365-worldwide        )
**Description:** Events involving accounts and objects in Office 365 and other cloud apps and services. Currently available in preview, the CloudAppEvents table in the advanced hunting schema contains information about activities in various cloud apps and services, specifically Microsoft Teams and Exchange Online. Use this reference to construct queries that return information from this table. This table will expand to include more activities monitored by Microsoft Cloud App Security. Eventually, this table will include file activity currently stored in the AppFileEvents table. Microsoft will provide additional guidance as more data moves to this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **ActionType** | Type of activity that triggered the event
| **Application** | Application that performed the recorded action
| **ApplicationId** | Unique identifier for the application
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **IsAdminOperation** | Indicates whether the activity was performed by an administrator
| **DeviceType** | Type of the device
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7
| **IPAddress** | IP address assigned to the device during communication
| **IsAnonymousProxy** | Indicates whether the IP address belongs to a known anonymous proxy
| **CountryCode** | Two-letter code indicating the country where the client IP address is geolocated
| **City** | City where the client IP address is geolocated
| **ISP** | Internet service provider associated with the IP address
| **UserAgent** | User agent information from the web browser or other client application
| **ActivityType** | Type of activity that triggered the event
| **ActivityObjects** | List of objects, such as files or folders, that were involved in the recorded activity
| **ObjectName** | Name of the object that the recorded action was applied to
| **ObjectType** | The type of object, such as a file or a folder, that the recorded action was applied to
| **ObjectId** | Unique identifier of the object that the recorded action was applied to
| **ReportId** | Unique identifier for the event
| **RawEventData** | Raw event information from the source application or service in JSON format
| **AdditionalFields** | Additional information about the entity or event

### CloudAppEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **SearchDataInsightsSubscription** | -
| **SearchMtpStatus** | -
| **SearchAlert** | -
| **SearchTIKustoClusterInformation** | -
| **ValidaterbacAccessCheck** | -
| **MailItemsAccessed** | -
| **SearchCustomTag** | -
| **Get-PolicyConfig** | -
| **SearchCustomerInsight** | -
| **Get-RoleGroup** | -
| **SearchAlertAggregate** | -
| **SearchAggTPSReportData** | -
| **Get-Label** | -
| **SearchAggSafeLinksReport** | -
| **Get-SupervisoryReviewReport** | -

## AADSpnSignInEventsBeta
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-aadsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about sign-in events initiated by Azure Active Directory (AAD) service principal or managed identities. The AADSignInEventsBeta table is currently in beta and is being offered on a short-term basis to allow you to hunt through Azure Active Directory (AAD) sign-in events. We will eventually move all sign-in schema information to the IdentityLogonEvents table. Customers who can access Microsoft 365 Defender through the Azure Security Center’s integrated Microsoft Defender for Endpoint solution, but do not have licenses for Microsoft Defender for Office, Microsoft Defender for Identity, or Microsoft Cloud App Security, will not be able to view this schema. The AADSignInEventsBeta table in the advanced hunting schema contains information about Azure Active Directory interactive and non-interactive sign-ins. Learn more about sign-ins in Azure Active Directory sign-in activity reports - preview. Sse this reference to construct queries that return information from the table. For information on other tables in the advanced hunting schema, see the advanced hunting reference.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **Application** | Application that performed the recorded action
| **ApplicationId** | Unique identifier for the application
| **IsManagedIdentity** | Indicates whether the sign-in was initiated by a managed identity
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes
| **CorrelationId** | Unique identifier of the sign-in event
| **ServicePrincipalName** | Name of the service principal that initiated the sign-in
| **ServicePrincipalId** | Unique identifier of the service principal that initiated the sign-in
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character.
| **ResourceId** | Unique identifier of the resource accessed
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed
| **IPAddress** | IP address assigned to the device during communication
| **Country** | Country/Region where the account user is located
| **State** | State where the sign-in occurred, if available
| **City** | City where the client IP address is geolocated
| **Latitude** | The north to south coordinates of the sign-in location
| **Longitude** | The east to west coordinates of the sign-in location
| **RequestId** | Unique identifier of the request
| **ReportId** | Unique identifier for the event

### Examples:

#### Most active managed identities:
```
// Most active Managed Identities
// Gets list of top 100 most active managed identities for the last day.
AADSpnSignInEventsBeta
| where Timestamp > ago(1d)
| where IsManagedIdentity == True
| summarize CountPerManagedIdentity = count() by ServicePrincipalId
| order by CountPerManagedIdentity desc
| take 100
```

#### Inactive service principals:
```
// Inactive Service Principals
// Service principals that had no sign-ins for the last 10d.
AADSpnSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0
| summarize LastSignIn = max(Timestamp) by ServicePrincipalId
| where LastSignIn < ago(10d)
| order by LastSignIn desc
```

## AADSignInEventsBeta
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-aadsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about Azure Active Directory (AAD) sign-in events either by a user (interactive) or a client on the user's behalf (non-interactive). The AADSignInEventsBeta table is currently in beta and is being offered on a short-term basis to allow you to hunt through Azure Active Directory (AAD) sign-in events. We will eventually move all sign-in schema information to the IdentityLogonEvents table. Customers who can access Microsoft 365 Defender through the Azure Security Center’s integrated Microsoft Defender for Endpoint solution, but do not have licenses for Microsoft Defender for Office, Microsoft Defender for Identity, or Microsoft Cloud App Security, will not be able to view this schema. The AADSignInEventsBeta table in the advanced hunting schema contains information about Azure Active Directory interactive and non-interactive sign-ins. Learn more about sign-ins in Azure Active Directory sign-in activity reports - preview. Use this reference to construct queries that return information from the table. For information on other tables in the advanced hunting schema, see the advanced hunting reference.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **Application** | Application that performed the recorded action
| **ApplicationId** | Unique identifier for the application
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes
| **CorrelationId** | Unique identifier of the sign-in event
| **SessionId** | Unique number assigned to a user by a website's server for the duration of the visit or session
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user.
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **AccountUpn** | User principal name (UPN) of the account
| **IsExternalUser** | Indicates if the user that signed in is external. Possible values: -1 (not set) , 0 (not external), 1 (external).
| **IsGuestUser** | Indicates whether the user that signed in is a guest in the tenant
| **AlternateSignInName** | On-premises user principal name (UPN) of the user signing in to Azure AD
| **LastPasswordChangeTimestamp** | Date and time when the user that signed in last changed their password
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character.
| **ResourceId** | Unique identifier of the resource accessed
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **AadDeviceId** | Unique identifier for the device in Azure AD
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7
| **DeviceTrustType** | Indicates the trust type of the device that signed in. For managed device scenarios only. Possible values are Workplace, AzureAd, and ServerAd.
| **IsManaged** | Indicates whether the device that initiated the sign-in is a managed device (1) or not a managed device (0)
| **IsCompliant** | Indicates whether the device that initiated the sign-in is compliant (1) or non-compliant (0)
| **AuthenticationProcessingDetails** | Details about the authentication processor
| **AuthenticationRequirement** | Type of authentication required for the sign-in. Possible values: multiFactorAuthentication (MFA was required) and singleFactorAuthentication (no MFA was required).
| **TokenIssuerType** | Indicates if the token issuer is Azure Active Directory (0) or Active Directory Federation Services (1)
| **RiskLevelAggregated** | Aggregated risk level during sign-in. Possible values: 0 (aggregated risk level not set), 1 (none), 10 (low), 50 (medium), or 100 (high).
| **RiskDetails** | Details about the risky state of the user that signed in
| **RiskState** | Indicates risky user state. Possible values: 0 (none), 1 (confirmed safe), 2 (remediated), 3 (dismissed), 4 (at risk), or 5 (confirmed compromised).
| **UserAgent** | User agent information from the web browser or other client application
| **ClientAppUsed** | Indicates the client app used
| **Browser** | Details about the version of the browser used to sign in
| **ConditionalAccessPolicies** | Details of the conditional access policies applied to the sign-in event
| **ConditionalAccessStatus** | Status of the conditional access policies applied to the sign-in. Possible values are 0 (policies applied), 1 (attempt to apply policies failed), or 2 (policies not applied).
| **IPAddress** | IP address assigned to the device during communication
| **Country** | Country/Region where the account user is located
| **State** | State where the sign-in occurred, if available
| **City** | City where the client IP address is geolocated
| **Latitude** | The north to south coordinates of the sign-in location
| **Longitude** | The east to west coordinates of the sign-in location
| **NetworkLocationDetails** | Network location details of the authentication processor of the sign-in event
| **RequestId** | Unique identifier of the request
| **ReportId** | Unique identifier for the event

### Examples:

#### Sign-ins to disabled accounts:
```
// Finds attempts to sign in to disabled accounts, listed by IP address
let timeRange = 14d;
AADSignInEventsBeta
| where  Timestamp >= ago(timeRange)
| where ErrorCode == '50057'  // The user account is disabled.
| summarize StartTime = min(Timestamp), EndTime = max(Timestamp), numberAccountsTargeted = dcount(AccountObjectId),
numberApplicationsTargeted = dcount(ApplicationId), accountSet = make_set(AccountUpn), applicationSet=make_set(Application),
numberLoginAttempts = count() by IPAddress
| extend timestamp = StartTime, IPCustomEntity = IPAddress
| order by numberLoginAttempts desc
```

#### User signing in from multiple locations:
```
// Users with multiple cities
// Get list of users that signed in from multiple cities for the last day.
AADSignInEventsBeta
| where Timestamp > ago(1d)
| summarize CountPerCity = dcount(City), citySet = make_set(City) by AccountUpn
| where CountPerCity > 1
| order by CountPerCity desc
```

# Email

## EmailEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-emailevents-table?view=o365-worldwide)
**Description:** Office 365 email events, including email delivery and blocking events. The EmailEvents table in the advanced hunting schema contains information about events involving the processing of emails on Microsoft Defender for Office 365. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | date and time when the record was generated
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system
| **SenderMailFromAddress** | Sender email address in the MAIL FROM header, also known as the envelope sender or the Return-Path address
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients
| **SenderMailFromDomain** | Sender domain in the MAIL FROM header, also known as the envelope sender or the Return-Path address
| **SenderFromDomain** | Sender domain in the FROM header, which is visible to email recipients on their email clients
| **SenderIPv4** | IPv4 address of the last detected mail server that relayed the message
| **SenderIPv6** | IPv6 address of the last detected mail server that relayed the message
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD
| **Subject** | Subject of the email
| **EmailClusterId** | Identifier for the group of similar emails clustered based on heuristic analysis of their contents
| **EmailDirection** | Direction of the email relative to your network: Inbound, Outbound, Intra-org
| **DeliveryAction** | Delivery action of the email: Delivered, Junked, Blocked, or Replaced
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items
| **PhishFilterVerdict** | Verdict of the email filtering stack on whether the email is phish: Phish, Not Phish
| **PhishDetectionMethod** | Phish filtering method used to detect the email as a phish: Malicious URL reputation, ATP Safe Links URL Detonation, Advanced phish filter, General phish filter, Anti-Spoof: Intra-org, Anti-spoof: external domain, Domain impersonation, User impersonation, Brand impersonation
| **MalwareFilterVerdict** | Verdict of the email filtering stack on whether the email contains malware: Malware, Not malware
| **MalwareDetectionMethod** | Method used to detect malware in the email: Antimalware engine, File reputation, ATP Safe Attachments
| **EmailAction** | Final action taken on the email based on filter verdict, policies, and user actions: Move message to junk mail folder, Add X-header, Modify subject, Redirect message, Delete message, send to quarantine, No action taken, Bcc message
| **EmailActionPolicy** | Action policy that took effect: Antispam high-confidence, Antispam, Antispam bulk mail, Antispam phishing, Anti-phishing domain impersonation, Anti-phishing user impersonation, Anti-phishing spoof, Anti-phishing graph impersonation, Antimalware Safe Attachments, Enterprise Transport Rules (ETR)
| **EmailActionPolicyGuid** | Unique identifier for the policy that determined the final mail action
| **AttachmentCount** | Number of attachments in the email
| **UrlCount** | Number of embedded URLs in the email
| **EmailLanguage** | Detected language of the email content
| **ReportId** | Unique identifier for the event
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname
| **SenderObjectId** | Unique identifier for the sender’s account in Azure AD
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats
| **ThreatNames** | Detection name for malware or other threats found
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email
| **OrgLevelAction** | Action taken on the email in response to matches to a policy defined at the organizational level
| **OrgLevelPolicy** | Organizational policy that triggered the action taken on the email
| **UserLevelAction** | Action taken on the email in response to matches to a mailbox policy defined by the recipient
| **UserLevelPolicy** | End user mailbox policy that triggered the action taken on the email
| **Connectors** | Custom instructions that define organizational mail flow and how the email was routed
| **ConfidenceLevel** | List of confidence levels of any spam or phishing verdicts. For spam, this column shows the spam confidence level (SCL), indicating if the email was skipped (-1), found to be not spam (0,1), found to be spam with moderate confidence (5,6), or found to be spam with high confidence (9). For phishing, this column displays whether the confidence level is "High" or "Low".

### Examples:

#### Phishing emails from the top ten sender domains:
```
//Get the number of phishing emails from the top ten sender domains
EmailEvents
| where PhishFilterVerdict == "Phish"
| summarize Count = count() by SenderFromDomain
| top 10 by Count
```

#### Emails with malware:
```
EmailEvents
| where MalwareFilterVerdict == "Malware"
| limit 500
```

## EmailAttachmentInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-emailattachmentinfo-table?view=o365-worldwide)
**Description:** Information about files attached to Office 365 emails. The EmailAttachmentInfo table in the advanced hunting schema contains information about attachments on emails processed by Microsoft Defender for Office 365. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD
| **FileName** | Name of the file that the recorded action was applied to
| **FileType** | File extension type
| **SHA256** | SHA-256 of the file that the recorded action was applied to
| **MalwareFilterVerdict** | Verdict of the email filtering stack on whether the email contains malware: Malware, Not malware
| **MalwareDetectionMethod** | Method used to detect malware in the email: Antimalware engine, File reputation, ATP Safe Attachments
| **ReportId** | Unique identifier for the event
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname
| **SenderObjectId** | Unique identifier for the sender’s account in Azure AD
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats
| **ThreatNames** | Detection name for malware or other threats found
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email

### Examples:

#### Files from malicious sender:
```
FileName // Finds the first appearance of files sent by a malicious sender in your organization
let MaliciousSender = "<insert the sender email address>";
EmailAttachmentInfo
| where Timestamp > ago(7d)
| where SenderFromAddress =~ MaliciousSender
| project SHA256 = tolower(SHA256)
| join (
DeviceFileEvents
| where Timestamp > ago(7d)
) on SHA256
| summarize FirstAppearance = min(Timestamp) by DeviceName, SHA256, FileName
```

#### Emails to external domains with attachments:
```
EmailEvents
| where EmailDirection == "Outbound" and AttachmentCount > 0
| join EmailAttachmentInfo on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, FileName, AttachmentCount
| take 100
```

## EmailUrlInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-emailurlinfo-table?view=o365-worldwide)
**Description:** Information about URLs on Office 365 emails. The EmailUrlInfo table in the advanced hunting schema contains information about URLs on emails and attachments processed by Microsoft Defender for Office 365. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365
| **Url** | Full Url from email
| **UrlDomain** | <no documentation>
| **ReportId** | Unique identifier for the event

### Examples:

#### URLs in an email:
```
let myEmailId = "<insert your email NetworkMessageId>";
EmailEvents
| where NetworkMessageId == myEmailId
| join EmailUrlInfo on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, Url, UrlCount
```

## EmailPostDeliveryEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-emailpostdeliveryevents-table?view=o365-worldwide)
**Description:** Security events that occur post-delivery, after Office 365 has delivered an email message to the recipient mailbox. The EmailPostDeliveryEvents table in the advanced hunting schema contains information about post-delivery actions taken on email messages processed by Microsoft 365. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system
| **Action** | Action taken on the entity
| **ActionType** | Type of activity that triggered the event
| **ActionTrigger** | Indicates whether an action was triggered by an administrator (manually or through approval of a pending automated action), or by some special mechanism, such as a ZAP or Dynamic Delivery
| **ActionResult** | Result of the action
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items
| **ReportId** | Unique identifier for the event

### Examples:

#### Post-delivery administrator actions:
```
EmailPostDeliveryEvents
| where ActionTrigger == 'AdminAction'
| limit 100
```

#### Unremediated post-delivery phishing email detections:
```
 EmailPostDeliveryEvents
| where ActionType == 'Phish ZAP' and ActionResult == 'Error'
| join EmailEvents on NetworkMessageId, RecipientEmailAddress
```

#### Full email process details:
```
let mySender = "<insert sender email address>";
let subject = "<insert email subject>";
EmailEvents
| where SenderFromAddress == mySender and Subject == subject
| join EmailPostDeliveryEvents on NetworkMessageId, RecipientEmailAddress
```

# Threat & Vulnerability Management

## DeviceTvmSoftwareInventoryVulnerabilities
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicetvmsoftwareinventoryvulnerabilities-table?view=o365-worldwide)
**Description:** Inventory of software on devices as well as any known vulnerabilities in these software products. The DeviceTvmSoftwareInventoryVulnerabilities table in the advanced hunting schema contains the Threat & Vulnerability Management inventory of software on your devices as well as any known vulnerabilities in these software products. This table also includes operating system information, CVE IDs, and vulnerability severity information. Use this reference to construct queries that return information from the table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **DeviceId** | Unique identifier for the machine in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the machine
| **OSPlatform** | Platform of the operating system running on the machine. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7.
| **OSVersion** | Version of the operating system running on the machine
| **OSArchitecture** | Architecture of the operating system running on the machine
| **SoftwareVendor** | Name of the software vendor
| **SoftwareName** | Name of the software product
| **SoftwareVersion** | Version number of the software product
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape

## DeviceTvmSoftwareVulnerabilitiesKB
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table?view=o365-worldwide)
**Description:** Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available. The DeviceTvmSoftwareVulnerabilitiesKB table in the advanced hunting schema contains the list of vulnerabilities Threat & Vulnerability Management assesses devices for. Use this reference to construct queries that return information from the table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system
| **CvssScore** | Severity score assigned to the security vulnerability under th Common Vulnerability Scoring System (CVSS)
| **IsExploitAvailable** | Indicates whether exploit code for the vulnerability is publicly available
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape
| **LastModifiedTime** | Date and time the item or related metadata was last modified
| **PublishedDate** | Date vulnerability was disclosed to public
| **VulnerabilityDescription** | Description of vulnerability and associated risks
| **AffectedSoftware** | List of all software products affected by the vulnerability

## DeviceTvmSecureConfigurationAssessment
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicetvmsecureconfigurationassessment-table?view=o365-worldwide)
**Description:** Threat & Vulnerability Management assessment events, indicating the status of various security configurations on devices. Each row in the DeviceTvmSecureConfigurationAssessment table contains an assessment event for a specific security configuration from Threat & Vulnerability Management. Use this reference to check the latest assessment results and determine whether devices are compliant.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7.
| **Timestamp** | Date and time when the record was generated
| **ConfigurationId** | Unique identifier for a specific configuration
| **ConfigurationCategory** | Category or grouping to which the configuration belongs: Application, OS, Network, Accounts, Security controls
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features.
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10)
| **IsCompliant** | Indicates whether the configuration or policy is properly configured
| **IsApplicable** | Indicates whether the configuration or policy applies to the device
| **Context** | Additional contextual information about the configuration or policy
| **IsExpectedUserImpact** | Indicates whether there will be user impact if the configuration or policy is applied

## DeviceTvmSecureConfigurationAssessmentKB
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicetvmsecureconfigurationassessmentkb-table?view=o365-worldwide)
**Description:** Knowledge base of various security configurations used by Threat & Vulnerability Management to assess devices; includes mappings to various standards and benchmarks. The DeviceTvmSecureConfigurationAssessmentKB table in the advanced hunting schema contains information about the various secure configurations — such as whether a device has automatic updates on — checked by Threat & Vulnerability Management. It also includes risk information, related industry benchmarks, and applicable MITRE ATT&CK techniques and tactics. Use this reference to construct queries that return information from the table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **ConfigurationId** | Unique identifier for a specific configuration
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10)
| **ConfigurationName** | Display name of the configuration
| **ConfigurationDescription** | Description of the configuration
| **RiskDescription** | Description of the associated risk
| **ConfigurationCategory** | Category or grouping to which the configuration belongs: Application, OS, Network, Accounts, Security controls
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features.
| **ConfigurationBenchmarks** | List of industry benchmarks recommending the same or similar configuration
| **Tags** | List of Mitre ATT&CK framework techniques related to the configuration
| **RemediationOptions** | List of Mitre ATT&CK framework tactics related to the configuration

# Devices

## DeviceInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-deviceinfo-table?view=o365-worldwide)
**Description:** Machine information, including OS information. The DeviceInfo table in the advanced hunting schema contains information about devices in the organization, including OS version, active users, and computer name. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ClientVersion** | Version of the endpoint agent or sensor running on the machine
| **PublicIP** | Public IP address used by the onboarded machine to connect to the Windows Defender ATP service. This could be the IP address of the machine itself, a NAT device, or a proxy
| **OSArchitecture** | Architecture of the operating system running on the machine
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7
| **OSBuild** | Build version of the operating system running on the machine
| **IsAzureADJoined** | Boolean indicator of whether machine is joined to the Azure Active Directory
| **AadDeviceId** | Unique identifier for the device in Azure AD
| **LoggedOnUsers** | List of all users that are logged on the machine at the time of the event in JSON array format
| **RegistryDeviceTag** | Device tag added through the registry
| **OSVersion** | Version of the operating system running on the machine
| **MachineGroup** | Machine group of the machine. This group is used by role-based access control to determine access to the machine
| **ReportId** | Unique identifier for the event
| **AdditionalFields** | Additional information about the entity or event

### Examples:

#### Devices with outdated operating systems:
```
//List devices running operating systems older than Windows 10
DeviceInfo
| where todecimal(OSVersion) < 10
| summarize by DeviceId, DeviceName, OSVersion, OSPlatform, OSBuild
```

#### Logged on users:
```
let myDevice = "<insert your device ID>";
DeviceInfo
| where Timestamp between (datetime(2020-05-19) .. datetime(2020-05-20)) and DeviceId == myDevice
| project LoggedOnUsers
| mvexpand todynamic(LoggedOnUsers) to typeof(string)
| summarize by LoggedOnUsers
```

## DeviceNetworkInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicenetworkevents-table?view=o365-worldwide)
**Description:** Network properties of machines, including adapters, IP and MAC addresses, as well as connected networks and domains. The DeviceNetworkEvents table in the advanced hunting schema contains information about network connections and related events. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **NetworkAdapterName** | Name of the network adapter
| **MacAddress** | MAC address of the network adapter
| **NetworkAdapterType** | Network adapter type
| **NetworkAdapterStatus** | Operational status of the network adapter
| **TunnelType** | Tunneling protocol, if the interface is used for this purpose, for example 6to4, Teredo, ISATAP, PPTP, SSTP, and SSH
| **ConnectedNetworks** | Networks that the adapter is connected to. Each JSON element in the array contains the network name, category (public, private or domain), a description, and a flag indicating if it’s connected publicly to the internet
| **DnsAddresses** | DNS server addresses in JSON array format
| **IPv4Dhcp** | IPv4 address of DHCP server
| **IPv6Dhcp** | IPv6 address of DHCP server
| **DefaultGateways** | Default gateway addresses in JSON array format
| **IPAddresses** | JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and the IP class (RFC 1918 & RFC 4291)
| **ReportId** | Unique identifier for the event
| **NetworkAdapterVendor** | Name of the manufacturer or vendor of the network adapter

### Examples:

#### Devices with a specific IP address:
```
let pivotTimeParam = datetime(2020-05-18 19:51:00);
let ipAddressParam = "192.168.1.5";
DeviceNetworkInfo
| where Timestamp between ((pivotTimeParam-15m) ..30m)
    and IPAddresses contains strcat("\", ipAddressParam, \"")
    and NetworkAdapterStatus == "Up"
//// Optional - add filters to make sure machine is part of the relevant network (and not using that IP address as part of another private network).
//// For example:
// and ConnectedNetworks contains "corp.contoso.com"
// and IPv4Dhcp == "10.164.3.12"
// and DefaultGateways contains "\"10.164.3.1\"
| project DeviceName, Timestamp, IPAddresses, TimeDifference=abs(Timestamp-pivotTimeParam)
// In case multiple machines have reported from that IP address arround that time, start with the ones reporting closest to pivotTimeParam
| sort by TimeDifference asc
```

## DeviceProcessEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-deviceprocessevents-table?view=o365-worldwide)
**Description:** Process creation and related events. The DeviceProcessEvents table in the advanced hunting schema contains information about process creation and related events. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to
| **SHA256** | SHA-256 of the file that the recorded action was applied to
| **MD5** | MD5 hash of the file that the recorded action was applied to
| **FileSize** | Size of the file in bytes
| **ProcessVersionInfoCompanyName** | Company name from the version information of the newly created process
| **ProcessVersionInfoProductName** | Product name from the version information of the newly created process
| **ProcessVersionInfoProductVersion** | Product version from the version information of the newly created process
| **ProcessVersionInfoInternalFileName** | Internal file name from the version information of the newly created process
| **ProcessVersionInfoOriginalFileName** | Original file name from the version information of the newly created process
| **ProcessVersionInfoFileDescription** | Description from the version information of the newly created process
| **ProcessId** | Process ID (PID) of the newly created process
| **ProcessCommandLine** | Command line used to create the new process
| **ProcessIntegrityLevel** | Integrity level of the newly created process. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet downloaded. These integrity levels influence permissions to resources.
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated)
| **ProcessCreationTime** | Date and time the process was created
| **AccountDomain** | Domain of the account
| **AccountName** | User name of the account
| **AccountSid** | Security Identifier (SID) of the account
| **AccountUpn** | User principal name (UPN) of the account
| **AccountObjectId** | Unique identifier for the account in Azure AD
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts.
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **InitiatingProcessSignerType** | Type of file signer of the process (image file) that initiated the event
| **InitiatingProcessSignatureStatus** | Information about the signature status of the process (image file) that initiated the event
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity
| **AdditionalFields** | Additional information about the entity or event

### DeviceProcessEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **ProcessCreated** | A process was launched on the device.

### Examples:

#### Clearing of event logs:
```
//Check process command lines for attempts to clear event logs
let myDevice = "<insert your device ID>";
DeviceProcessEvents
| where DeviceId == myDevice and Timestamp > ago(7d) and ((InitiatingProcessCommandLine contains "wevtutil" and (InitiatingProcessCommandLine contains ' cl ' or InitiatingProcessCommandLine contains ' clear ' or InitiatingProcessCommandLine contains ' clearev ' ))
or (InitiatingProcessCommandLine contains ' wmic ' and InitiatingProcessCommandLine contains ' cleareventlog '))
```

#### PowerShell activity triggered by malicious email:
```
// Finds PowerShell activities that occurred right after an email was received from a malicious sender
let MaliciousSender = "malicious.sender@domain.com";
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromAddress =~ MaliciousSender
| project EmailRecievedTime = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0])
| join (
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| where InitiatingProcessParentFileName =~ "outlook.exe"
| project ProcessCreateTime = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
) on AccountName
| where (ProcessCreateTime - EmailRecievedTime) between (0min .. 30min)
```

## DeviceNetworkEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicenetworkevents-table?view=o365-worldwide)
**Description:** Network connection and related events. The DeviceNetworkEvents table in the advanced hunting schema contains information about network connections and related events. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **RemoteIP** | IP address that was being connected to
| **RemotePort** | TCP port on the remote device that was being connected to
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to
| **LocalIP** | IP address assigned to the local machine used during communication
| **LocalPort** | TCP port on the local machine used during communication
| **Protocol** | Protocol used during the communication
| **LocalIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity
| **AdditionalFields** | Additional information about the entity or event

### DeviceNetworkEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **ConnectionFailed** | An attempt to establish a network connection from the device failed.
| **ConnectionFound** | An active network connection was found on the device.
| **ConnectionRequest** | The device initiated a network connection.
| **ConnectionSuccess** | A network connection was successfully established from the device.
| **InboundConnectionAccepted** | The device accepted a network connection initiated by another device.
| **ListeningConnectionCreated** | A process has started listening for connections on a certain port.

### Examples:

#### Tor client connections:
```
//Find network connections by known Tor clients
DeviceNetworkEvents
| where Timestamp > ago(7d) and InitiatingProcessFileName in~ ("tor.exe", "meek-client.exe")
// Returns MD5 hashes of files used by Tor, to enable you to block them.
// We count how prevalent each file is (by devices) and show examples for some of them (up to 5 device names per hash).
| summarize DeviceCount=dcount(DeviceId), DeviceNames=make_set(DeviceName, 5) by InitiatingProcessMD5
| order by DeviceCount desc
```

#### PowerShell download activity:
```
// Finds PowerShell execution events that could involve a download
union DeviceProcessEvents, DeviceNetworkEvents
| where Timestamp > ago(7d)
// Pivoting on PowerShell processes
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
// Suspicious commands
| where ProcessCommandLine has_any("WebClient",
 "DownloadFile",
 "DownloadData",
 "DownloadString",
"WebRequest",
"Shellcode",
"http",
"https")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| top 100 by Timestamp
```

## DeviceFileEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicefileevents-table?view=o365-worldwide)
**Description:** File creation, modification, and other file system events. The DeviceFileEvents table in the advanced hunting schema contains information about file creation, modification, and other file system events. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to
| **SHA256** | SHA-256 of the file that the recorded action was applied to
| **MD5** | MD5 hash of the file that the recorded action was applied to
| **FileOriginUrl** | URL where the file was downloaded from
| **FileOriginReferrerUrl** | URL of the web page that links to the downloaded file
| **FileOriginIP** | IP address where the file was downloaded from
| **PreviousFolderPath** | Original folder containing the file before the recorded action was applied
| **PreviousFileName** | Original name of the file that was renamed as a result of the action
| **FileSize** | Size of the file in bytes
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **RequestProtocol** | Network protocol, if applicable, used to initiate the activity: Unknown, Local, SMB, or NFS
| **RequestSourceIP** | IPv4 or IPv6 address of the remote device that initiated the activity
| **RequestSourcePort** | Source port on the remote device that initiated the activity
| **RequestAccountName** | User name of account used to remotely initiate the activity
| **RequestAccountDomain** | Domain of the account used to remotely initiate the activity
| **RequestAccountSid** | Security Identifier (SID) of the account used to remotely initiate the activity
| **ShareName** | Name of shared folder containing the file
| **SensitivityLabel** | Label applied to an email, file, or other content to classify it for information protection
| **SensitivitySubLabel** | Sublabel applied to an email, file, or other content to classify it for information protection; sensitivity sublabels are grouped under sensitivity labels but are treated independently
| **IsAzureInfoProtectionApplied** | Indicates whether the file is encrypted by Azure Information Protection
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity
| **AdditionalFields** | Additional information about the entity or event

### DeviceFileEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **FileCreated** | A file was created on the device.
| **FileModified** | A file on the device was modified.
| **FileRenamed** | A file on the device was renamed.
| **FileDeleted** | A file was deleted.

### Examples:

#### Sensitive file uploads:
```
//Get the list of sensitive files that were uploaded to a cloud app or service
DeviceFileEvents
| where SensitivityLabel in ("Highly Confidential", "Confidential") and Timestamp > ago(1d)
| project FileName, FolderPath, DeviceId, DeviceName , ActionType , SensitivityLabel , Timestamp
| summarize LastTimeSeenOnDevice = max(Timestamp) by FileName, FolderPath, DeviceName , DeviceId , SensitivityLabel
| join (CloudAppEvents
| where ActionType == "FileUploaded" and Timestamp > ago(1d) | extend FileName = tostring(RawEventData.SourceFileName) ) on FileName
| project UploadTime = Timestamp, ActionType, Application, FileName, SensitivityLabel, AccountDisplayName ,
AccountObjectId , IPAddress, CountryCode , LastTimeSeenOnDevice, DeviceName, DeviceId, FolderPath
| limit 100
```

#### Copy or move file:
```
let myFile = '<file SHA1>';
DeviceFileEvents
| where SHA1 == myFile and ActionType == 'FileCreated'
| limit 100
```

## DeviceRegistryEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-deviceregistryevents-table?view=o365-worldwide)
**Description:** Creation and modification of registry entries. The DeviceRegistryEvents table in the advanced hunting schema contains information about the creation and modification of registry entries. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **RegistryKey** | Registry key that the recorded action was applied to
| **RegistryValueType** | Data type, such as binary or string, of the registry value that the recorded action was applied to
| **RegistryValueName** | Name of the registry value that the recorded action was applied to
| **RegistryValueData** | Data of the registry value that the recorded action was applied to
| **PreviousRegistryKey** | Original registry key before it was modified
| **PreviousRegistryValueName** | Original name of the registry value before it was modified
| **PreviousRegistryValueData** | Original data of the registry value before it was modified
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity

### DeviceRegistryEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **RegistryValueDeleted** | A registry value was deleted.
| **RegistryKeyDeleted** | A registry key was deleted.
| **RegistryKeyCreated** | A registry key was created.
| **RegistryValueSet** | The data for a registry value was modified.
| **RegistryKeyRenamed** | A registry key was renamed.

### Examples:

#### Devices with security controls turned off:
```
//Detecting disabling of Defender:
DeviceRegistryEvents
| where RegistryKey has @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender"
    and (RegistryValueName has "DisableRealtimeProtection"
    or RegistryValueName has "DisableRealtimeMonitoring"
    or RegistryValueName has "DisableBehaviorMonitoring"
    or RegistryValueName has "DisableIOAVProtection"
    or RegistryValueName has "DisableScriptScanning"
    or RegistryValueName has "DisableBlockAtFirstSeen")
    // Where 1 means it’s disabled.
and RegistryValueData has "1" and isnotempty(PreviousRegistryValueData) and Timestamp > ago(7d)
| project Timestamp, ActionType, DeviceId , DeviceName, RegistryKey, RegistryValueName , RegistryValueData,  PreviousRegistryValueData
```

#### Autostart services:
```
//Check a specific device for the services set to automatically start with Windows
let myDevice = "<insert your device ID>";
DeviceRegistryEvents
| where DeviceId == ""//myDevice
    and ActionType in ("RegistryValueSet")
    and RegistryKey matches regex @"HKEY_LOCAL_MACHINE\\SYSTEM\\.*\\Services\\.*"
    and RegistryValueName == "Start" and RegistryValueData == "2"
| limit 100
```

## DeviceLogonEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicelogonevents-table?view=o365-worldwide)
**Description:** Sign-ins and other authentication events. The DeviceLogonEvents table in the advanced hunting schema contains information about user logons and other authentication events on devices. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service
| **AccountDomain** | Domain of the account
| **AccountName** | User name of the account
| **AccountSid** | Security Identifier (SID) of the account
| **Protocol** | Protocol used during the communication
| **FailureReason** | Information explaining why the recorded action failed
| **IsLocalAdmin** | Boolean indicator of whether the user is a local administrator on the machine
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information.
| **RemoteIP** | IP address that was being connected to
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast
| **RemotePort** | TCP port on the remote device that was being connected to
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity
| **AdditionalFields** | Additional information about the entity or event

### DeviceLogonEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **LogonSuccess** | A user successfully logged on to the device.
| **LogonAttempted** | A user attempted to log on to the device.
| **LogonFailed** | A user attempted to logon to the device but failed.

### Examples:

#### Admin logons:
```
//List authentication events by members of the local administrator group or the built-in administrator account
let myDevice = "<insert your device ID>";
DeviceLogonEvents
| where  IsLocalAdmin == '1'  and Timestamp > ago(7d) and DeviceId == "00d20207bebd88fea19194bd775a372875c7ab1f"
| limit 500
```

#### Logons after receipt of malicious emails:
```
//Find logons that occurred right after malicious email was received
let MaliciousEmail=EmailEvents
| where ThreatTypes has "Malware"
| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
MaliciousEmail
| join (
DeviceLogonEvents
| project LogonTime = Timestamp, AccountName, DeviceName
) on AccountName
| where (LogonTime - TimeEmail) between (0min.. 30min)
| take 10
```

## DeviceImageLoadEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-deviceimageloadevents-table?view=o365-worldwide)
**Description:** DLL loading events. The DeviceImageLoadEvents table in the advanced hunting schema contains information about DLL loading events. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to
| **SHA256** | SHA-256 of the file that the recorded action was applied to
| **MD5** | MD5 hash of the file that the recorded action was applied to
| **FileSize** | Size of the file in bytes
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources.
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity

### DeviceImageLoadEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **ImageLoaded** | A dynamic link library (DLL) was loaded.

## DeviceEvents
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-deviceevents-table?view=o365-worldwide)
**Description:** Multiple event types, including events triggered by security controls such as Windows Defender Antivirus and exploit protection. The miscellaneous device events or DeviceEvents table in the advanced hunting schema contains information about various event types, including events triggered by security controls, such as Windows Defender Antivirus and exploit protection. Use this reference to construct queries that return information from this table.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **ActionType** | Type of activity that triggered the event
| **FileName** | Name of the file that the recorded action was applied to
| **FolderPath** | Folder containing the file that the recorded action was applied to
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to
| **SHA256** | SHA-256 of the file that the recorded action was applied to
| **MD5** | MD5 hash of the file that the recorded action was applied to
| **FileSize** | Size of the file in bytes
| **AccountDomain** | Domain of the account
| **AccountName** | User name of the account
| **AccountSid** | Security Identifier (SID) of the account
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information.
| **ProcessId** | Process ID (PID) of the newly created process
| **ProcessCommandLine** | Command line used to create the new process
| **ProcessCreationTime** | Date and time the process was created
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated)
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts
| **RegistryKey** | Registry key that the recorded action was applied to
| **RegistryValueName** | Name of the registry value that the recorded action was applied to
| **RegistryValueData** | Data of the registry value that the recorded action was applied to
| **RemoteIP** | IP address that was being connected to
| **RemotePort** | TCP port on the remote device that was being connected to
| **LocalIP** | IP address assigned to the local machine used during communication
| **LocalPort** | TCP port on the local machine used during communication
| **FileOriginUrl** | URL where the file was downloaded from
| **FileOriginIP** | IP address where the file was downloaded from
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available.
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event
| **InitiatingProcessFileName** | Name of the process that initiated the event
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts.
| **ReportId** | Unique identifier for the event
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity
| **AdditionalFields** | Additional information about the entity or event

### DeviceEvents ActionTypes:
| Field | Description |
| ---: | :--- |
| **AccountCheckedForBlankPassword** | An account was checked for a blank password.
| **AntivirusDefinitionsUpdated** | Security intelligence updates for Windows Defender Antivirus were applied successfully.
| **AntivirusDefinitionsUpdateFailed** | Security intelligence updates for Windows Defender Antivirus were not applied.
| **AntivirusDetection** | Windows Defender Antivirus detected a threat.
| **AntivirusEmergencyUpdatesInstalled** | Emergency security intelligence updates for Windows Defender Antivirus were applied.
| **AntivirusError** | Windows Defender Antivirus encountered an error while taking action on malware or a potentially unwanted application.
| **AntivirusMalwareActionFailed** | "Windows Defender Antivirus attempted to take action on malware or a potentially unwanted application but the action failed."
| **AntivirusMalwareBlocked** | "Windows Defender Antivirus blocked files or activity involving malware potentially unwanted applications or suspicious behavior."
| **AntivirusScanCancelled** | A Windows Defender Antivirus scan was cancelled.
| **AntivirusScanCompleted** | A Windows Defender Antivirus scan completed successfully.
| **AntivirusScanFailed** | A Windows Defender Antivirus scan did not complete successfully.
| **AppControlAppInstallationAudited** | Application control detected the installation of an untrusted app.
| **AppControlAppInstallationBlocked** | Application control blocked the installation of an untrusted app.
| **AppControlCodeIntegrityDriverRevoked** | Application control found a driver with a revoked certificate.
| **AppControlCodeIntegrityImageAudited** | Application control detected an executable file that violated code integrity policies.
| **AppControlCodeIntegrityImageRevoked** | Application control found an executable file with a revoked certificate.
| **AppControlCodeIntegrityPolicyAudited** | Application control detected a code integrity policy violation.
| **AppControlCodeIntegrityPolicyBlocked** | Application control blocked a code integrity policy violation.
| **AppControlExecutableAudited** | Application control detected the use of an untrusted executable.
| **AppControlExecutableBlocked** | Application control blocked the use of an untrusted executable.
| **AppControlPackagedAppAudited** | Application control detected the use of an untrusted packaged app.
| **AppControlPackagedAppBlocked** | Application control blocked the installation of an untrusted packaged app.
| **AppControlScriptAudited** | Application control detected the use of an untrusted script.
| **AppControlScriptBlocked** | Application control blocked the use of an untrusted script.
| **AppGuardBrowseToUrl** | A URL was accessed from within an application guard container.
| **AppGuardCreateContainer** | Application guard initiated an isolated container.
| **AppGuardLaunchedWithUrl** | The opening of an untrusted URL has initiated an application guard container.
| **AppGuardResumeContainer** | Application guard resumed an isolated container from a suspended state.
| **AppGuardStopContainer** | Application guard stopped an isolated container.
| **AppGuardSuspendContainer** | Application guard suspended an isolated container.
| **AsrAdobeReaderChildProcessAudited** | An attack surface reduction rule detected Adobe Reader creating a child process.
| **AsrAdobeReaderChildProcessBlocked** | An attack surface reduction rule blocked Adobe Reader from creating a child process.
| **AsrExecutableEmailContentAudited** | An attack surface reduction rule detected the launch of executable content from an email client and or webmail.
| **AsrExecutableEmailContentBlocked** | An attack surface reduction rule blocked executable content from an email client and or webmail.
| **AsrExecutableOfficeContentAudited** | An attack surface reduction rule detected an Office application creating executable content.
| **AsrExecutableOfficeContentBlocked** | An attack surface reduction rule blocked an Office application from creating executable content.
| **AsrLsassCredentialTheftAudited** | An attack surface reduction rule detected possible credential theft from lsass.exe.
| **AsrLsassCredentialTheftBlocked** | An attack surface reduction rule blocked possible credential theft from lsass.exe.
| **AsrObfuscatedScriptAudited** | An attack surface reduction rule detected the execution of scripts that appear obfuscated.
| **AsrObfuscatedScriptBlocked** | An attack surface reduction rule blocked the execution of scripts that appear obfuscated.
| **AsrOfficeChildProcessAudited** | An attack surface reduction rule detected an Office application spawning a child process.
| **AsrOfficeChildProcessBlocked** | An attack surface reduction rule blocked an Office application from creating child processes.
| **AsrOfficeCommAppChildProcessAudited** | An attack surface reduction rule detected an Office communication app attempting to spawn a child process.
| **AsrOfficeCommAppChildProcessBlocked** | An attack surface reduction rule blocked an Office communication app from spawning a child process.
| **AsrOfficeMacroWin32ApiCallsAudited** | An attack surface reduction rule detected Win32 API calls from Office macros.
| **AsrOfficeMacroWin32ApiCallsBlocked** | An attack surface reduction rule blocked Win32 API calls from Office macros.
| **AsrOfficeProcessInjectionAudited** | An attack surface reduction rule detected an Office application injecting code into other processes.
| **AsrOfficeProcessInjectionBlocked** | An attack surface reduction rule blocked an Office application from injecting code into other processes.
| **AsrPersistenceThroughWmiAudited** | An attack surface reduction rule detected an attempt to establish persistence through WMI event subscription.
| **AsrPersistenceThroughWmiBlocked** | An attack surface reduction rule blocked an attempt to establish persistence through WMI event subscription.
| **AsrPsexecWmiChildProcessAudited** | An attack surface reduction rule detected the use of PsExec or WMI commands to spawn a child process.
| **AsrPsexecWmiChildProcessBlocked** | An attack surface reduction rule blocked the use of PsExec or WMI commands to spawn a child process.
| **AsrRansomwareAudited** | An attack surface reduction rule detected ransomware activity.
| **AsrRansomwareBlocked** | An attack surface reduction rule blocked ransomware activity.
| **AsrScriptExecutableDownloadAudited** | An attack surface reduction rule detected JavaScript or VBScript code launching downloaded executable content.
| **AsrScriptExecutableDownloadBlocked** | An attack surface reduction rule blocked JavaScript or VBScript code from launching downloaded executable content.
| **AsrUntrustedExecutableAudited** | An attack surface reduction rule detected the execution of an untrusted file that doesn't meet criteria for age or prevalence.
| **AsrUntrustedExecutableBlocked** | An attack surface reduction rule blocked the execution of an untrusted file that doesn't meet criteria for age or prevalence.
| **AsrUntrustedUsbProcessAudited** | An attack surface reduction rule detected the execution of an untrusted and unsigned processes from a USB device.
| **AsrUntrustedUsbProcessBlocked** | An attack surface reduction rule blocked the execution of an untrusted and unsigned processes from a USB device.
| **BrowserLaunchedToOpenUrl** | A web browser opened a URL that originated as a link in another application.
| **ControlFlowGuardViolation** | Control Flow Guard terminated an application after detecting an invalid function call
| **ControlledFolderAccessViolationAudited** | Controlled folder access detected an attempt to modify a protected folder.
| **ControlledFolderAccessViolationBlocked** | Controlled folder access blocked an attempt to modify a protected folder.
| **CreateRemoteThreadApiCall** | A thread that runs in the virtual address space of another process was created.
| **CredentialsBackup** | The backup feature in Credential Manager was initiated
| **DeviceBootAttestationInfo** | System Guard generated a boot-time attestation report.
| **DirectoryServiceObjectCreated** | An object was added to the directory service.
| **DirectoryServiceObjectModified** | An object in the directory service was modified.
| **FilePrinted** | A file was sent to a printer device for printing.
| **DnsQueryResponse** | A response to a DNS query was sent.
| **DriverLoad** | A driver was loaded.
| **ExploitGuardAcgAudited** | Arbitrary code guard (ACG) in exploit protection detected an attempt to modify code page permissions or create unsigned code pages.
| **ExploitGuardAcgEnforced** | Arbitrary code guard (ACG) blocked an attempt to modify code page permissions or create unsigned code pages.
| **ExploitGuardChildProcessAudited** | Exploit protection detected the creation of a child process.
| **ExploitGuardChildProcessBlocked** | Exploit protection blocked the creation of a child process.
| **ExploitGuardEafViolationAudited** | Export address filtering (EAF) in exploit protection detected possible exploitation activity.
| **ExploitGuardEafViolationBlocked** | Export address filtering (EAF) in exploit protection blocked possible exploitation activity.
| **ExploitGuardIafViolationAudited** | Import address filtering (IAF) in exploit protection detected possible exploitation activity.
| **ExploitGuardIafViolationBlocked** | Import address filtering (IAF) in exploit protection blocked possible exploitation activity.
| **ExploitGuardLowIntegrityImageAudited** | Exploit protection detected the launch of a process from a low-integrity file.
| **ExploitGuardLowIntegrityImageBlocked** | Exploit protection blocked the launch of a process from a low-integrity file.
| **ExploitGuardNonMicrosoftSignedAudited** | Exploit protection detected the launch of a process from an image file that is not signed by Microsoft.
| **ExploitGuardNonMicrosoftSignedBlocked** | Exploit protection blocked the launch of a process from an image file that is not signed by Microsoft.
| **ExploitGuardRopExploitAudited** | Exploit protection detected possible return-object programming (ROP) exploitation.
| **ExploitGuardRopExploitBlocked** | Exploit protection blocked possible return-object programming (ROP) exploitation.
| **ExploitGuardSharedBinaryAudited** | Exploit protection detected the launch of a process from a remote shared file.
| **ExploitGuardSharedBinaryBlocked** | Exploit protection blocked the launch of a process from a file in a remote device.
| **ExploitGuardWin32SystemCallAudited** | Exploit protection detected a call to the Windows system API.
| **ExploitGuardWin32SystemCallBlocked** | Exploit protection blocked a call to the Windows system API.
| **FirewallInboundConnectionBlocked** | A firewall or another application blocked an inbound connection using the Windows Filtering Platform.
| **FirewallInboundConnectionToAppBlocked** | The firewall blocked an inbound connection to an app.
| **FirewallOutboundConnectionBlocked** | A firewall or another application blocked an outbound connection using the Windows Filtering Platform.
| **FirewallServiceStopped** | The firewall service was stopped.
| **GetAsyncKeyStateApiCall** | The GetAsyncKeyState function was called. This function can be used to obtain the states of input keys and buttons.
| **GetClipboardData** | The GetClipboardData function was called. This function can be used obtain the contents of the system clipboard.
| **LdapSearch** | An LDAP search was performed.
| **LogonRightsSettingEnabled** | Interactive logon rights on the machine were granted to a user.
| **MemoryRemoteProtect** | A process has modified the protection mask for a memory region used by another process. This might allow execution of content from non-executable memory.
| **NetworkProtectionUserBypassEvent** | A user has bypassed network protection and accessed a blocked IP address, domain, or URL.
| **NetworkShareObjectAccessChecked** | A request was made to access a file or folder shared on the network and permissions to the share was evaluated.
| **NtAllocateVirtualMemoryApiCall** | Memory was allocated for a process.
| **NtAllocateVirtualMemoryRemoteApiCall** | Memory was allocated for a process remotely.
| **NtMapViewOfSectionRemoteApiCall** | A section of a process's memory was mapped by calling the function NtMapViewOfSection.
| **NtProtectVirtualMemoryApiCall** | The protection attributes for allocated memory was modified.
| **OpenProcessApiCall** | The OpenProcess function was called indicating an attempt to open a handle to a local process and potentially manipulate that process.
| **PasswordChangeAttempt** | An attempt to change a user password was made.
| **PnpDeviceConnected** | A plug and play (PnP) device was attached.
| **PowerShellCommand** | A PowerShell alias function filter cmdlet external script application script workflow or configuration was executed from a PowerShell host process.
| **PrintJobBlocked** | Device control prevented an untrusted printer from printing.
| **ProcessCreatedUsingWmiQuery** | A process was created using Windows Management Instrumentation (WMI).
| **ProcessPrimaryTokenModified** | A process's primary token was modified.
| **QueueUserApcRemoteApiCall** | An asynchronous procedure call (APC) was scheduled to execute in a user-mode thread.
| **ReadProcessMemoryApiCall** | The ReadProcessMemory function was called indicating that a process read data from the process memory of another process.
| **RemoteDesktopConnection** | A Remote Desktop connection was established
| **RemoteWmiOperation** | A Windows Management Instrumentation (WMI) operation was initiated from a remote device.
| **SafeDocFileScan** | A document was sent to the cloud for analysis while in protected view.
| **ScheduledTaskCreated** | A scheduled task was created.
| **ScheduledTaskDeleted** | A scheduled task was deleted.
| **ScheduledTaskDisabled** | A scheduled task was turned off.
| **ScheduledTaskEnabled** | A scheduled task was turned on.
| **ScheduledTaskUpdated** | A scheduled task was updated.
| **ScreenshotTaken** | A screenshot was taken.
| **SecurityLogCleared** | The security log was cleared.
| **SecurityGroupCreated** | A security group was created
| **SecurityGroupDeleted** | A security group was deleted.
| **SensitiveFileRead** | A file that matched DLP policy was accessed.
| **ServiceInstalled** | A service was installed. This is based on Windows event ID 4697, which requires the advanced security audit setting Audit Security System Extension.
| **SetThreadContextRemoteApiCall** | The context of a thread was set from a user-mode process.
| **ShellLinkCreateFileEvent** | A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application.
| **SmartScreenAppWarning** | SmartScreen warned about running a downloaded application that is untrusted or malicious.
| **SmartScreenExploitWarning** | SmartScreen warned about opening a web page that contains an exploit.
| **SmartScreenUrlWarning** | SmartScreen warned about opening a low-reputation URL that might be hosting malware or is a phishing site.
| **SmartScreenUserOverride** | A user has overridden a SmartScreen warning and continued to open an untrusted app or a low-reputation URL.
| **UntrustedWifiConnection** | A connection was established to an open Wi-Fi access point that is set to connect automatically.
| **UsbDriveMounted** | A USB storage device was mounted as a drive.
| **UsbDriveUnmounted** | A USB storage device was unmounted.
| **UserAccountAddedToLocalGroup** | A user was added to a security-enabled local group.
| **UserAccountCreated** | A local SAM account or a domain account was created.
| **UserAccountDeleted** | A user account was deleted.
| **UserAccountModified** | A user account was modified.
| **UserAccountRemovedFromLocalGroup** | A user was removed from a security-enabled local group.
| **WmiBindEventFilterToConsumer** | A filter for WMI events was bound to a consumer. This enables listening for all kinds of system events and triggering corresponding actions, including potentially malicious ones.
| **WriteToLsassProcessMemory** | The WriteProcessMemory function was called indicating that a process has written data into memory for another process.

### Examples:

#### USB devices:
```
//Get the list the USB devices attached to a device in the past week
let myDevice = "<insert your device ID>";
DeviceEvents
| where ActionType == "UsbDriveMount" and Timestamp > ago(7d) and DeviceId == myDevice
| extend ProductName = todynamic(AdditionalFields)["ProductName"], SerialNumber = todynamic(AdditionalFields)["SerialNumber"],
Manufacturer = todynamic(AdditionalFields)["Manufacturer"], Volume = todynamic(AdditionalFields)["Volume"]
| summarize lastInsert = max(Timestamp) by tostring(ProductName), tostring(SerialNumber), tostring(Manufacturer), tostring(Volume)
```

#### Antivirus scan events:
```
// Get antivirus scan events, including completed and cancelled scans
let myDevice = "<insert your device ID>";
DeviceEvents
| where ActionType startswith "AntivirusScan"  and Timestamp > ago(7d) and DeviceId == myDevice
| extend ScanDesc = parse_json(AdditionalFields)
|project Timestamp, DeviceName, ActionType, Domain = ScanDesc.Domain, ScanId= ScanDesc.ScanId, User = ScanDesc.User, ScanParametersIndex = ScanDesc.ScanParametersIndex, ScanTypeIndex = ScanDesc.ScanTypeIndex
```

## DeviceFileCertificateInfo
[[Link to MS-Source]](https://docs.microsoft.com/en-US/microsoft-365/security/mtp/advanced-hunting-devicefilecertificateinfo-table?view=o365-worldwide)
**Description:** Certificate information of signed files obtained from certificate verification events on endpoints. The DeviceFileCertificateInfo table in the advanced hunting schema contains information about file signing certificates. This table uses data obtained from certificate verification activities regularly performed on files on endpoints.

### Table Schema:
| Field | Description |
| ---: | :--- |
| **Timestamp** | Date and time when the record was generated
| **DeviceId** | Unique identifier for the device in the service
| **DeviceName** | Fully qualified domain name (FQDN) of the device
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to
| **IsSigned** | Indicates whether the file is signed
| **SignatureType** | Indicates whether signature information was read as embedded content in the file itself or read from an external catalog file
| **Signer** | Information about the signer of the file
| **SignerHash** | Unique hash value identifying the signer
| **Issuer** | Information about the issuing certificate authority (CA)
| **IssuerHash** | Unique hash value identifying issuing certificate authority (CA)
| **CertificateSerialNumber** | Identifier for the certificate that is unique to the issuing certificate authority (CA)
| **CrlDistributionPointUrls** | JSON array listing the URLs of network shares that contain certificates and certificate revocation lists (CRLs)
| **CertificateCreationTime** | Date and time the certificate was created
| **CertificateExpirationTime** | Date and time the certificate is set to expire
| **CertificateCountersignatureTime** | Date and time the certificate was countersigned
| **IsTrusted** | Indicates whether the file is trusted based on the results of the WinVerifyTrust function, which checks for unknown root certificate information, invalid signatures, revoked certificates, and other questionable attributes
| **IsRootSignerMicrosoft** | Indicates whether the signer of the root certificate is Microsoft
| **ReportId** | Unique identifier for the event

### Examples:

#### Files with spoofed Microsoft certificates:
```
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where IsSigned == 1
    and IsTrusted == 1
    and IsRootSignerMicrosoft == 1
| where SignatureType == "Embedded"
| where Issuer !startswith "Microsoft"
    and Issuer !startswith "Windows"
| project Timestamp, DeviceName,SHA1,Issuer,IssuerHash,Signer,SignerHash,
    CertificateCreationTime,CertificateExpirationTime,CrlDistributionPointUrls
| limit 10
```
