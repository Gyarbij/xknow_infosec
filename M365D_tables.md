# Microsoft Defender 365 Advanced hunting full schema reference (Streaming API overview)

[MS 365 Advanced hunting schema tables reference](https://docs.microsoft.com/en-US/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide)

[MS 365 Defender/Azure Sentinel detections/custom KQL querries](https://github.com/Azure/Azure-Sentinel)

### Table Schema:
| Acronym | Product |
| :--- | :--- |
| **MS365D** | Microsoft 365 Defender
| **MDI** | Microsoft Defender for Identity
| **MDE** | Microsoft Defender for Endpoint
| **MDA** | Microsoft Defender for Cloud Apps
| **MDO** | Microsoft Defender for Office 365
| **TVM** | Microsoft Defender Vulnerability Management

Schema Overview
=================
  * [Alerts](#alerts)
    * [Table: AlertInfo](#table-alertinfo)
    * [Table: AlertEvidence](#table-alertevidence)
    * [Table: BehaviorInfo](#table-behaviorinfo)
    * [Table: BehaviorEntities](#table-behaviorentities)
  * [Apps & identities](#apps--identities)
    * [Table: IdentityInfo](#table-identityinfo)
    * [Table: IdentityLogonEvents](#table-identitylogonevents)
    * [Table: IdentityQueryEvents](#table-identityqueryevents)
    * [Table: IdentityDirectoryEvents](#table-identitydirectoryevents)
    * [Table: CloudAppEvents](#table-cloudappevents)
    * [Table: AADSpnSignInEventsBeta](#table-aadspnsignineventsbeta)
    * [Table: AADSignInEventsBeta](#table-aadsignineventsbeta)
  * [Email](#email)
    * [Table: EmailEvents](#table-emailevents)
    * [Table: EmailAttachmentInfo](#table-emailattachmentinfo)
    * [Table: EmailUrlInfo](#table-emailurlinfo)
    * [Table: EmailPostDeliveryEvents](#table-emailpostdeliveryevents)
    * [Table: UrlClickEvents](#table-urlclickevents)
  * [Threat & Vulnerability Management](#threat--vulnerability-management)
    * [Table: DeviceTvmSoftwareVulnerabilities](#table-devicetvmsoftwarevulnerabilities)
    * [Table: DeviceTvmSoftwareVulnerabilitiesKB](#table-devicetvmsoftwarevulnerabilitieskb)
    * [Table: DeviceTvmSecureConfigurationAssessment](#table-devicetvmsecureconfigurationassessment)
    * [Table: DeviceTvmSecureConfigurationAssessmentKB](#table-devicetvmsecureconfigurationassessmentkb)
    * [Table: DeviceTvmSoftwareInventory](#table-devicetvmsoftwareinventory)
    * [Table: DeviceTvmInfoGathering](#table-devicetvminfogathering)
    * [Table: DeviceTvmInfoGatheringKB](#table-devicetvminfogatheringkb)
    * [Table: DeviceTvmSoftwareEvidenceBeta](#table-devicetvmsoftwareevidencebeta)
  * [Devices](#devices)
    * [Table: DeviceEvents](#table-deviceevents)
    * [Table: DeviceFileCertificateInfo](#table-devicefilecertificateinfo)
    * [Table: DeviceFileEvents](#table-devicefileevents)
    * [Table: DeviceImageLoadEvents](#table-deviceimageloadevents)
    * [Table: DeviceInfo](#table-deviceinfo)
    * [Table: DeviceLogonEvents](#table-devicelogonevents)
    * [Table: DeviceNetworkEvents](#table-devicenetworkevents)
    * [Table: DeviceNetworkInfo](#table-devicenetworkinfo)
    * [Table: DeviceProcessEvents](#table-deviceprocessevents)
    * [Table: DeviceRegistryEvents](#table-deviceregistryevents)

Missing tables (addons): DeviceTvmHardwareFirmware, DeviceTvmCertificateInfo, DeviceTvmBrowserExtensions, DeviceTvmBrowserExtensionsKB, DeviceBaselineComplianceProfiles, DeviceBaselineComplianceAssessment, DeviceBaselineComplianceAssessmentKB

## Table: AADSignInEventsBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-aadsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about Azure Active Directory (AAD) sign-in events either by a user (interactive) or a client on the user's behalf (non-interactive)

### Table Schema:
| Field | Description |
| --- | --- |
| **RiskState** | Indicates risky user state. Possible values: 0 (none), 1 (confirmed safe), 2 (remediated), 3 (dismissed), 4 (at risk), or 5 (confirmed compromised). |
| **RiskEventTypes** | Array of risk event types applicable to the event |
| **UserAgent** | User agent information from the web browser or other client application |
| **Browser** | Details about the version of the browser used to sign in |
| **ClientAppUsed** | Indicates the client app used |
| **RiskLevelDuringSignIn** | User risk level at sign-in |
| **AuthenticationProcessingDetails** | Details about the authentication processor |
| **IsCompliant** | Indicates whether the device that initiated the event is compliant or not |
| **AuthenticationRequirement** | Type of authentication required for the sign-in. Possible values: multiFactorAuthentication (MFA was required) and singleFactorAuthentication (no MFA was required). |
| **RiskLevelAggregated** | Aggregated risk level during sign-in. Possible values: 0 (aggregated risk level not set), 1 (none), 10 (low), 50 (medium), or 100 (high). |
| **TokenIssuerType** | Indicates if the token issuer is Azure Active Directory (0) or Active Directory Federation Services (1) |
| **Longitude** | The east to west coordinates of the sign-in location |
| **Latitude** | The north to south coordinates of the sign-in location |
| **NetworkLocationDetails** | Network location details of the authentication processor of the sign-in event |
| **ReportId** | Unique identifier for the event |
| **RequestId** | Unique identifier of the request |
| **City** | City where the client IP address is geolocated |
| **ConditionalAccessStatus** | Status of the conditional access policies applied to the sign-in. Possible values are 0 (policies applied), 1 (attempt to apply policies failed), or 2 (policies not applied). |
| **ConditionalAccessPolicies** | Details of the conditional access policies applied to the sign-in event |
| **IPAddress** | IP address assigned to the device during communication |
| **State** | State where the sign-in occurred, if available |
| **Country** | Country/Region where the account user is located |
| **IsManaged** | Indicates whether the endpoint has been onboarded to and is managed by Microsoft Defender for Endpoint |
| **SessionId** | Unique number assigned to a user by a website's server for the duration of the visit or session |
| **CorrelationId** | Unique identifier of the sign-in event |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes |
| **Application** | Application that performed the recorded action |
| **Timestamp** | Date and time when the record was generated |
| **ApplicationId** | Unique identifier for the application  |
| **EndpointCall** | Information about the AAD endpoint that the request was sent to and the type of request sent during sign in |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed |
| **AadDeviceId** | Unique identifier for the device in Azure AD |
| **DeviceTrustType** | Indicates the trust type of the device that signed in. For managed device scenarios only. Possible values are Workplace, AzureAd, and ServerAd. |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **ResourceId** | Unique identifier of the resource accessed |
| **IsGuestUser** | Indicates whether the user that signed in is a guest in the tenant |
| **IsExternalUser** | Indicates whether a user inside the network does not belong to the organizationâ€™s domain |
| **AlternateSignInName** | On-premises user principal name (UPN) of the user signing in to Azure AD |
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character. |
| **LastPasswordChangeTimestamp** | Date and time when the user that signed in last changed their password |

### Examples:

### Gets a list of users that signed in from multiple locations in the last 24 hours
```
// Users with multiple cities 
// Get list of users that signed in from multiple cities for the last day. 
AADSignInEventsBeta 
| where Timestamp > ago(1d)
| summarize CountPerCity = dcount(City), citySet = make_set(City) by AccountUpn 
| where CountPerCity > 1
| order by CountPerCity desc
```

### Finds attempts to sign in to disabled accounts, listed by IP address
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


## Table: AADSpnSignInEventsBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-aadspnsignineventsbeta-table?view=o365-worldwide)
**Description:** Information about sign-in events initiated by Azure Active Directory (AAD) service principal or managed identities

### Table Schema:
| Field | Description |
| --- | --- |
| **Country** | Country/Region where the account user is located |
| **State** | State where the sign-in occurred, if available |
| **ResourceTenantId** | Unique identifier of the tenant of the resource accessed |
| **IPAddress** | IP address assigned to the device during communication |
| **City** | City where the client IP address is geolocated |
| **RequestId** | Unique identifier of the request |
| **ReportId** | Unique identifier for the event |
| **Latitude** | The north to south coordinates of the sign-in location |
| **Longitude** | The east to west coordinates of the sign-in location |
| **ResourceId** | Unique identifier of the resource accessed |
| **ApplicationId** | Unique identifier for the application  |
| **IsManagedIdentity** | Indicates whether the sign-in was initiated by a managed identity |
| **Timestamp** | Date and time when the record was generated |
| **Application** | Application that performed the recorded action |
| **ErrorCode** | Contains the error code if a sign-in error occurs. To find a description of a specific error code, visit https://aka.ms/AADsigninsErrorCodes |
| **ServicePrincipalId** | Unique identifier of the service principal that initiated the sign-in |
| **ResourceDisplayName** | Display name of the resource accessed. The display name can contain any character. |
| **CorrelationId** | Unique identifier of the sign-in event |
| **ServicePrincipalName** | Name of the service principal that initiated the sign-in |

### Examples:

### Gets list of the top 100 most active managed identities in the last 24 hours
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

### Gets list of service principals with no sign-ins in the last ten days
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


## Table: AlertEvidence

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertevidence-table?view=o365-worldwide)
**Description:** Files, IP addresses, URLs, users, or devices associated with alerts

### Table Schema:
| Field | Description |
| --- | --- |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **EmailSubject** | Subject of the email |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **DeviceId** | Unique identifier for the device in the service |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountDomain** | Domain of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **Severity** | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert |
| **AdditionalFields** | Additional information about the entity or event |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **ApplicationId** | Unique identifier for the application  |
| **Application** | Application that performed the recorded action |
| **ProcessCommandLine** | Command line used to create the new process |
| **OAuthApplicationId** | Unique identifier of the third-party OAuth application |
| **AccountName** | User name of the account |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **ServiceSource** | Product or service that provided the alert information |
| **EvidenceRole** | How the entity is involved in an alert, indicating whether it is impacted or is merely related |
| **EntityType** | Type of object, such as a file, a process, a device, or a user |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the alert |
| **AlertId** | Unique identifier for the alert |
| **Timestamp** | Date and time when the record was generated |
| **Categories** | List of categories that the information belongs to, in JSON array format |
| **Title** | Title of the alert |
| **ThreatFamily** | Malware family that the suspicious or malicious file or process has been classified under |
| **FileSize** | Size of the file in bytes |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **RemoteIP** | IP address that was being connected to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **EvidenceDirection** | Indicates whether the entity is the source or the destination of a network connection |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **FolderPath** | Folder containing the file that the recorded action was applied to |

### Examples:

### List all alerts involving a specific device
```
let myDevice = "<insert your device ID>";
let deviceName = "<insert your device name>";
AlertEvidence
| extend DeviceName = todynamic(AdditionalFields)["HostName"]
| where EntityType == "Machine" and (DeviceId == myDevice or DeviceName == deviceName)
| project DeviceId, DeviceName, AlertId 
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, DeviceId, DeviceName
```

### List all alerts involving a particular user account
```
let userID = "<inert your AAD user ID>";
let userSid = "<inert your user SID>";
AlertEvidence
| where EntityType == "User" and (AccountObjectId == userID or AccountSid == userSid )
| join AlertInfo on AlertId
| project Timestamp, AlertId, Title, Category , Severity , ServiceSource , DetectionSource , AttackTechniques, AccountObjectId, AccountName, AccountDomain , AccountSid 
```


## Table: AlertInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-alertinfo-table?view=o365-worldwide)
**Description:** Alerts from Microsoft Defender for Endpoint, Microsoft Defender for Office 365, Microsoft Cloud App Security, and Microsoft Defender for Identity, including severity information and threat categorization

### Table Schema:
| Field | Description |
| --- | --- |
| **ServiceSource** | Product or service that provided the alert information |
| **Severity** | Indicates the potential impact (high, medium, or low) of the threat indicator or breach activity identified by the alert |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the alert |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **AlertId** | Unique identifier for the alert |
| **Timestamp** | Date and time when the record was generated |
| **Category** | Type of threat indicator or breach activity identified by the alert |
| **Title** | Title of the alert |

### Examples:

### Get the number of alerts by severity
```
AlertInfo
| summarize alertsCount=dcount(AlertId) by Severity
| sort by alertsCount desc
```

### Get the number of alerts by MITRE ATT&CK technique
```
AlertInfo
| where isnotempty(AttackTechniques)
| mvexpand todynamic(AttackTechniques) to typeof(string)
| summarize AlertCount = dcount(AlertId) by AttackTechniques
| sort by AlertCount desc
```


## Table: BehaviorEntities

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorentities-table?view=o365-worldwide)
**Description:** Contains information about entities (file, process, device, user, and others) that are involved in a behavior

### Table Schema:
| Field | Description |
| --- | --- |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **EmailSubject** | Subject of the email |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **DeviceId** | Unique identifier for the device in the service |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountDomain** | Domain of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **AdditionalFields** | Additional information about the behavior |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **ProcessCommandLine** | Command line used to create the new process |
| **Application** | Application that performed the recorded action |
| **EmailClusterId** | Identifier for the group of similar emails clustered based on heuristic analysis of their contents |
| **OAuthApplicationId** | Unique identifier of the third-party OAuth application |
| **ApplicationId** | Unique identifier for the application  |
| **AccountName** | User name of the account |
| **DataSources** | Products or services that provided information for the behavior |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **EntityRole** | Indicates whether the entity is impacted or merely related |
| **EntityType** | Type of object, such as a file, a process, a device, or a user |
| **ServiceSource** | Product or service that identified the behavior |
| **BehaviorId** | Unique identifier for the behavior |
| **Timestamp** | Date and time when the record was generated |
| **Categories** | Type of threat indicator or breach activity identified by the behavior |
| **ActionType** | Type of behavior |
| **ThreatFamily** | Malware family that the suspicious or malicious file or process has been classified under |
| **FileSize** | Size of the file in bytes |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **RemoteIP** | IP address that was being connected to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **DetailedEntityRole** | The role of the entity in the behavior |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **FolderPath** | Folder containing the file that the recorded action was applied to |

## Table: BehaviorInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-behaviorinfo-table?view=o365-worldwide)
**Description:** Contains information about behaviors, which in the context of Microsoft 365 Defender refers to a conclusion or insight based on one or more raw events, which can provide analysts more context in investigations

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountUpn** | User principal name (UPN) of the account |
| **DeviceId** | Unique identifier for the device in the service |
| **DataSources** | Products or services that provided information for the behavior |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AdditionalFields** | Additional information about the behavior |
| **EndTime** | Date and time of the last activity related to the behavior |
| **StartTime** | Date and time of the first activity related to the behavior |
| **DetectionSource** | Detection technology or sensor that identified the notable component or activity |
| **ActionType** | Type of behavior |
| **BehaviorId** | Unique identifier for the behavior |
| **Timestamp** | Date and time when the record was generated |
| **Description** | Description of behavior |
| **ServiceSource** | Product or service that identified the behavior |
| **AttackTechniques** | MITRE ATT&CK techniques associated with the activity that triggered the behavior |
| **Categories** | Type of threat indicator or breach activity identified by the behavior |

### Examples:

### Get behaviors associated with a specific MITRE ATT&CK technique in the last week
```
let technique = 'Valid Accounts (T1078)';
BehaviorInfo
| where Timestamp > ago(7d)
| where AttackTechniques has technique
```

### All behaviors in the last week on users that raised an alert in the last week
```
AlertEvidence
| where Timestamp > ago(7d)
| where EntityType == 'User' | distinct AccountObjectId
| join (BehaviorInfo | where Timestamp > ago(7d)) on AccountObjectId
```


## Table: CloudAppEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-cloudappevents-table?view=o365-worldwide)
**Description:** Events involving accounts and objects in Office 365 and other cloud apps and services

### Table Schema:
| Field | Description |
| --- | --- |
| **ObjectType** | The type of object, such as a file or a folder, that the recorded action was applied to |
| **ObjectId** | Unique identifier of the object that the recorded action was applied to |
| **ReportId** | Unique identifier for the event |
| **ObjectName** | Name of the object that the recorded action was applied to |
| **UserAgent** | User agent information from the web browser or other client application |
| **ActivityType** | Type of activity that triggered the event |
| **ActivityObjects** | List of objects, such as files or folders, that were involved in the recorded activity |
| **AccountType** | Type of user account, indicating its general role and access levels, such as Regular, System, Admin, Application |
| **UserAgentTags** | More information provided by Microsoft Cloud App Security in a tag in the user agent field. Can have any of the following values: Native client, Outdated browser, Outdated operating system, Robot |
| **RawEventData** | Raw event information from the source application or service in JSON format |
| **AdditionalFields** | Additional information about the entity or event |
| **IPCategory** | Additional information about the IP address |
| **IsExternalUser** | Indicates whether a user inside the network does not belong to the organizationâ€™s domain |
| **IsImpersonated** | Indicates whether the activity was performed by one user on behalf of another (impersonated) user |
| **IPTags** | Customer-defined information applied to specific IP addresses and IP address ranges |
| **ISP** | Internet service provider associated with  the IP address |
| **AppInstanceId** | Unique identifier for the instance of an application |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountId** | An identifier for the account as found by Microsoft Cloud App Security. Could be Azure Active Directory ID, user principal name, or other identifiers. |
| **ApplicationId** | Unique identifier for the application  |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **Application** | Application that performed the recorded action |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **IsAnonymousProxy** | Indicates whether the IP address belongs to a known anonymous proxy |
| **CountryCode** | Two-letter code indicating the country where the client IP address is geolocated |
| **City** | City where the client IP address is geolocated |
| **IPAddress** | IP address assigned to the device during communication |
| **IsAdminOperation** | Indicates whether the activity was performed by an administrator |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |

### Examples:

### Gives a list of sharing activities in cloud apps
```
// Gives a list of sharing activities in cloud apps
// Includes invitations, acceptances, requests and approvals for sharing files and folders in the cloud
CloudAppEvents
| where ActivityType == "Share"
| take 100
```

### Find app activity renaming .docx files to .doc on devices
```
// Find applications that renamed .docx files to .doc on devices
CloudAppEvents 
| where Timestamp > ago(3d)
| where Application in ("Microsoft OneDrive for Business", "Microsoft SharePoint Online") and ActionType == "FileRenamed"
| extend NewFileNameExtension = tostring(RawEventData.DestinationFileExtension)
| extend OldFileNameExtension = tostring(RawEventData.SourceFileExtension)
| extend OldFileName = tostring(RawEventData.SourceFileName)
| extend NewFileName = tostring(RawEventData.DestinationFileName)
| where NewFileNameExtension == "doc" and OldFileNameExtension == "docx" 
| project RenameTime = Timestamp, OldFileNameExtension, OldFileName, NewFileNameExtension, NewFileName, ActionType, Application, AccountDisplayName, AccountObjectId
| join kind=inner (
DeviceFileEvents 
| where Timestamp > ago(3d)
| project FileName, AccountObjectId = InitiatingProcessAccountObjectId , DeviceName, SeenOnDevice = Timestamp, FolderPath 
) on $left.NewFileName == $right.FileName, AccountObjectId
| project RenameTime, NewFileName, OldFileName, Application, AccountObjectId, AccountDisplayName, DeviceName , SeenOnDevice, FolderPath
```


## Table: DeviceEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceevents-table?view=o365-worldwide)
**Description:** Multiple event types, including events triggered by security controls such as Windows Defender Antivirus and exploit protection

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **FileOriginIP** | IP address where the file was downloaded from |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts. |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **FileSize** | Size of the file in bytes |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **AccountDomain** | Domain of the account |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountName** | User name of the account |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **RemoteIP** | IP address that was being connected to |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **FileOriginUrl** | URL where the file was downloaded from |
| **LocalPort** | TCP port on the local machine used during communication |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **ProcessCommandLine** | Command line used to create the new process |
| **ProcessId** | Process ID (PID) of the newly created process |
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information. |
| **ProcessCreationTime** | Date and time the process was created |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated) |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **MemoryRemoteProtect** | A process has modified the protection mask for a memory region used by another process. This might allow execution of content from non-executable memory. |
| **LogonRightsSettingEnabled** | Interactive logon rights on the machine were granted to a user. |
| **NamedPipeEvent** | A named pipe was created or opened. |
| **NetworkShareObjectAccessChecked** | A request was made to access a file or folder shared on the network and permissions to the share was evaluated. |
| **NetworkProtectionUserBypassEvent** | A user has bypassed network protection and accessed a blocked IP address, domain, or URL. |
| **LdapSearch** | An LDAP search was performed. |
| **FirewallOutboundConnectionBlocked** | A firewall or another application blocked an outbound connection using the Windows Filtering Platform. |
| **FirewallInboundConnectionToAppBlocked** | The firewall blocked an inbound connection to an app. |
| **FirewallServiceStopped** | The firewall service was stopped. |
| **GetClipboardData** | The GetClipboardData function was called. This function can be used obtain the contents of the system clipboard. |
| **GetAsyncKeyStateApiCall** | The GetAsyncKeyState function was called. This function can be used to obtain the states of input keys and buttons. |
| **OpenProcessApiCall** | The OpenProcess function was called indicating an attempt to open a handle to a local process and potentially manipulate that process. |
| **NtProtectVirtualMemoryApiCall** | The protection attributes for allocated memory was modified. |
| **PasswordChangeAttempt** | An attempt to change a user password was made. |
| **PnpDeviceAllowed** | Device control allowed a trusted plug and play (PnP) device. |
| **PlistPropertyModified** | A property in the plist was modified. |
| **NtMapViewOfSectionRemoteApiCall** | A section of a process's memory was mapped by calling the function NtMapViewOfSection. |
| **NetworkShareObjectDeleted** | A file or folder shared on the network was deleted. |
| **NetworkShareObjectAdded** | A file or folder was shared on the network. |
| **NetworkShareObjectModified** | A file or folder shared on the network was modified. |
| **NtAllocateVirtualMemoryRemoteApiCall** | Memory was allocated for a process remotely. |
| **NtAllocateVirtualMemoryApiCall** | Memory was allocated for a process. |
| **FirewallInboundConnectionBlocked** | A firewall or another application blocked an inbound connection using the Windows Filtering Platform. |
| **ExploitGuardIafViolationAudited** | Import address filtering (IAF) in exploit protection detected possible exploitation activity. |
| **ExploitGuardEafViolationBlocked** | Export address filtering (EAF) in exploit protection blocked possible exploitation activity. |
| **ExploitGuardIafViolationBlocked** | Import address filtering (IAF) in exploit protection blocked possible exploitation activity. |
| **ExploitGuardLowIntegrityImageBlocked** | Exploit protection blocked the launch of a process from a low-integrity file. |
| **ExploitGuardLowIntegrityImageAudited** | Exploit protection detected the launch of a process from a low-integrity file. |
| **ExploitGuardEafViolationAudited** | Export address filtering (EAF) in exploit protection detected possible exploitation activity. |
| **ExploitGuardAcgAudited** | Arbitrary code guard (ACG) in exploit protection detected an attempt to modify code page permissions or create unsigned code pages. |
| **DriverLoad** | A driver was loaded. |
| **ExploitGuardAcgEnforced** | Arbitrary code guard (ACG) blocked an attempt to modify code page permissions or create unsigned code pages. |
| **ExploitGuardChildProcessBlocked** | Exploit protection blocked the creation of a child process. |
| **ExploitGuardChildProcessAudited** | Exploit protection detected the creation of a child process. |
| **ExploitGuardSharedBinaryBlocked** | Exploit protection blocked the launch of a process from a file in a remote device. |
| **ExploitGuardSharedBinaryAudited** | Exploit protection detected the launch of a process from a remote shared file. |
| **ExploitGuardWin32SystemCallAudited** | Exploit protection detected a call to the Windows system API. |
| **FileTimestampModificationEvent** | File timestamp information was modified. |
| **ExploitGuardWin32SystemCallBlocked** | Exploit protection blocked a call to the Windows system API. |
| **ExploitGuardRopExploitBlocked** | Exploit protection blocked possible return-object programming (ROP) exploitation. |
| **ExploitGuardNetworkProtectionBlocked** | Network protection blocked a malicious or unwanted IP address domain or URL. |
| **ExploitGuardNetworkProtectionAudited** | Network protection detected an attempt to access a malicious or unwanted IP address domain or URL. |
| **ExploitGuardNonMicrosoftSignedAudited** | Exploit protection detected the launch of a process from an image file that is not signed by Microsoft. |
| **ExploitGuardRopExploitAudited** | Exploit protection detected possible return-object programming (ROP) exploitation. |
| **ExploitGuardNonMicrosoftSignedBlocked** | Exploit protection blocked the launch of a process from an image file that is not signed by Microsoft. |
| **PnpDeviceBlocked** | Device control blocked an untrusted plug and play (PnP) device. |
| **TamperingAttempt** | An attempt to change Microsoft Defender 365 settings was made. |
| **SmartScreenUserOverride** | A user has overridden a SmartScreen warning and continued to open an untrusted app or a low-reputation URL. |
| **UntrustedWifiConnection** | A connection was established to an open Wi-Fi access point that is set to connect automatically. |
| **UsbDriveMount** | A USB storage device was mounted as a drive. |
| **UsbDriveDriveLetterChanged** | The drive letter assigned to a mounted USB storage device was modified |
| **SmartScreenUrlWarning** | SmartScreen warned about opening a low-reputation URL that might be hosting malware or is a phishing site. |
| **SetThreadContextRemoteApiCall** | The context of a thread was set from a user-mode process. |
| **ServiceInstalled** | A service was installed. This is based on Windows event ID 4697, which requires the advanced security audit setting Audit Security System Extension. |
| **ShellLinkCreateFileEvent** | A specially crafted link file (.lnk) was generated. The link file contains unusual attributes that might launch malicious code along with a legitimate file or application. |
| **SmartScreenExploitWarning** | SmartScreen warned about opening a web page that contains an exploit. |
| **SmartScreenAppWarning** | SmartScreen warned about running a downloaded application that is untrusted or malicious. |
| **UserAccountRemovedFromLocalGroup** | A user was removed from a security-enabled local group. |
| **UserAccountModified** | A user account was modified. |
| **WmiBindEventFilterToConsumer** | A filter for WMI events was bound to a consumer. This enables listening for all kinds of system events and triggering corresponding actions, including potentially malicious ones. |
| **WriteToLsassProcessMemory** | The WriteProcessMemory function was called indicating that a process has written data into memory for another process. |
| **WriteProcessMemoryApiCall** | The WriteProcessMemory function was called indicating that a process has written data into memory for another process. |
| **UserAccountDeleted** | A user account was deleted. |
| **UsbDriveUnmount** | A USB storage device was unmounted. |
| **UsbDriveMounted** | A USB storage device was mounted as a drive. |
| **UsbDriveUnmounted** | A USB storage device was unmounted. |
| **UserAccountCreated** | A local SAM account or a domain account was created. |
| **UserAccountAddedToLocalGroup** | A user was added to a security-enabled local group. |
| **SensitiveFileRead** | A file that matched DLP policy was accessed or processes that are reading sensitive files such as ssh keys, Outlook mail archives etc. |
| **ReadProcessMemoryApiCall** | The ReadProcessMemory function was called indicating that a process read data from the process memory of another process. |
| **QueueUserApcRemoteApiCall** | An asynchronous procedure call (APC) was scheduled to execute in a user-mode thread. |
| **RemoteDesktopConnection** | A Remote Desktop connection was established |
| **RemovableStorageFileEvent** | Removable storage file activity matched a device control removable storage access control policy. |
| **RemoteWmiOperation** | A Windows Management Instrumentation (WMI) operation was initiated from a remote device. |
| **PTraceDetected** | A process trace (ptrace) was found to have occurred on this device. |
| **PowerShellCommand** | A PowerShell alias function filter cmdlet external script application script workflow or configuration was executed from a PowerShell host process. |
| **PnpDeviceConnected** | A plug and play (PnP) device was attached. |
| **PrintJobBlocked** | Device control prevented an untrusted printer from printing. |
| **ProcessPrimaryTokenModified** | A process's primary token was modified. |
| **ProcessCreatedUsingWmiQuery** | A process was created using Windows Management Instrumentation (WMI). |
| **ScreenshotTaken** | A screenshot was taken. |
| **ScheduledTaskUpdated** | A scheduled task was updated. |
| **SecurityGroupCreated** | A security group was created |
| **SecurityLogCleared** | The security log was cleared. |
| **SecurityGroupDeleted** | A security group was deleted. |
| **ScheduledTaskEnabled** | A scheduled task was turned on. |
| **SafeDocFileScan** | A document was sent to the cloud for analysis while in protected view. |
| **RemovableStoragePolicyTriggered** | Device control detected an attempted read/write/execute event from a removable storage device. |
| **ScheduledTaskCreated** | A scheduled task was created. |
| **ScheduledTaskDisabled** | A scheduled task was turned off. |
| **ScheduledTaskDeleted** | A scheduled task was deleted. |
| **AppControlPolicyApplied** | An application control policy was applied to the device. |
| **AppControlPackagedAppBlocked** | Application control blocked the installation of an untrusted packaged app. |
| **AppControlScriptAudited** | Application control detected the use of an untrusted script. |
| **AppGuardBrowseToUrl** | A URL was accessed from within an application guard container. |
| **AppControlScriptBlocked** | Application control blocked the use of an untrusted script. |
| **AppControlPackagedAppAudited** | Application control detected the use of an untrusted packaged app. |
| **AppControlCodeIntegrityPolicyLoaded** | An application control code integrity policy was loaded. |
| **AppControlCodeIntegrityPolicyBlocked** | Application control blocked a code integrity policy violation. |
| **AppControlCodeIntegritySigningInformation** | Application control signing information was generated. |
| **AppControlExecutableBlocked** | Application control blocked the use of an untrusted executable. |
| **AppControlExecutableAudited** | Application control detected the use of an untrusted executable. |
| **AppLockerBlockPackagedAppInstallation** | AppLocker prevented the installation of an untrusted packaged app. |
| **AppLockerBlockPackagedApp** | AppLocker prevented an untrusted packaged app from running. |
| **AppLockerBlockScript** | AppLocker prevented an untrusted script from running. |
| **AsrAdobeReaderChildProcessBlocked** | An attack surface reduction rule blocked Adobe Reader from creating a child process. |
| **AsrAdobeReaderChildProcessAudited** | An attack surface reduction rule detected Adobe Reader creating a child process. |
| **AppLockerBlockExecutable** | AppLocker prevented an untrusted executable from running. |
| **AppGuardLaunchedWithUrl** | The opening of an untrusted URL has initiated an application guard container. |
| **AppGuardCreateContainer** | Application guard initiated an isolated container. |
| **AppGuardResumeContainer** | Application guard resumed an isolated container from a suspended state. |
| **AppGuardSuspendContainer** | Application guard suspended an isolated container. |
| **AppGuardStopContainer** | Application guard stopped an isolated container. |
| **AppControlCodeIntegrityPolicyAudited** | Application control detected a code integrity policy violation. |
| **AntivirusMalwareBlocked** | Windows Defender Antivirus blocked files or activity involving malware potentially unwanted applications or suspicious behavior. |
| **AntivirusMalwareActionFailed** | Windows Defender Antivirus attempted to take action on malware or a potentially unwanted application but the action failed. |
| **AntivirusScanCancelled** | A Windows Defender Antivirus scan was cancelled. |
| **AntivirusScanFailed** | A Windows Defender Antivirus scan did not complete successfully. |
| **AntivirusScanCompleted** | A Windows Defender Antivirus scan completed successfully. |
| **AntivirusError** | Windows Defender Antivirus encountered an error while taking action on malware or a potentially unwanted application. |
| **AntivirusDefinitionsUpdated** | Security intelligence updates for Windows Defender Antivirus were applied successfully. |
| **AccountCheckedForBlankPassword** | An account was checked for a blank password. |
| **AntivirusDefinitionsUpdateFailed** | Security intelligence updates for Windows Defender Antivirus were not applied. |
| **AntivirusEmergencyUpdatesInstalled** | Emergency security intelligence updates for Windows Defender Antivirus were applied. |
| **AntivirusDetection** | Windows Defender Antivirus detected a threat. |
| **AppControlCodeIntegrityImageRevoked** | Application control found an executable file with a revoked certificate. |
| **AppControlCodeIntegrityImageAudited** | Application control detected an executable file that violated code integrity policies. |
| **AppControlCodeIntegrityOriginAllowed** | Application control allowed a file due to its good reputation (ISG) or installation source (managed installer). |
| **AppControlCodeIntegrityOriginBlocked** | Application control blocked a file due to its bad reputation (ISG) or installation source (managed installer). |
| **AppControlCodeIntegrityOriginAudited** | Application control would have blocked a file due to its bad reputation (ISG) or installation source (managed installer) if the policy was enforced. |
| **AppControlCodeIntegrityDriverRevoked** | Application control found a driver with a revoked certificate. |
| **AppControlAppInstallationAudited** | Application control detected the installation of an untrusted app. |
| **AntivirusTroubleshootModeEvent** | The troubleshooting mode in Microsoft Defender Antivirus was used. |
| **AppControlAppInstallationBlocked** | Application control blocked the installation of an untrusted app. |
| **AppControlCIScriptBlocked** | A script or MSI file generated by Windows LockDown Policy was blocked. |
| **AppControlCIScriptAudited** | A script or MSI file generated by Windows LockDown Policy was audited. |
| **AsrExecutableEmailContentAudited** | An attack surface reduction rule detected the launch of executable content from an email client and or webmail. |
| **BitLockerAuditCompleted** | An audit for BitLocker encryption was completed. |
| **AuditPolicyModification** | Changes in the Windows audit policy (which feed events to the event log). |
| **BluetoothPolicyTriggered** | A Bluetooth service activity was allowed or blocked by a device control policy. |
| **ControlFlowGuardViolation** | Control Flow Guard terminated an application after detecting an invalid function call |
| **BrowserLaunchedToOpenUrl** | A web browser opened a URL that originated as a link in another application. |
| **AsrVulnerableSignedDriverBlocked** | An attack surface reduction rule blocked a signed driver that has known vulnerabilities. |
| **AsrUntrustedExecutableBlocked** | An attack surface reduction rule blocked the execution of an untrusted file that doesn't meet criteria for age or prevalence. |
| **AsrUntrustedExecutableAudited** | An attack surface reduction rule detected the execution of an untrusted file that doesn't meet criteria for age or prevalence. |
| **AsrUntrustedUsbProcessAudited** | An attack surface reduction rule detected the execution of an untrusted and unsigned processes from a USB device. |
| **AsrVulnerableSignedDriverAudited** | An attack surface reduction rule detected a signed driver that has known vulnerabilities. |
| **AsrUntrustedUsbProcessBlocked** | An attack surface reduction rule blocked the execution of an untrusted and unsigned processes from a USB device. |
| **DlpPocPrintJob** | A file was sent to a printer device for printing. |
| **DirectoryServiceObjectModified** | An object in the directory service was modified. |
| **DnsQueryRequest** | A DNS request was initiated. |
| **DpapiAccessed** | Decription of saved sensitive data encrypted using DPAPI. |
| **DnsQueryResponse** | A response to a DNS query was sent. |
| **DirectoryServiceObjectCreated** | An object was added to the directory service. |
| **ControlledFolderAccessViolationBlocked** | Controlled folder access blocked an attempt to modify a protected folder. |
| **ControlledFolderAccessViolationAudited** | Controlled folder access detected an attempt to modify a protected folder. |
| **CreateRemoteThreadApiCall** | A thread that runs in the virtual address space of another process was created. |
| **DeviceBootAttestationInfo** | System Guard generated a boot-time attestation report. |
| **CredentialsBackup** | The backup feature in Credential Manager was initiated |
| **AsrScriptExecutableDownloadBlocked** | An attack surface reduction rule blocked JavaScript or VBScript code from launching downloaded executable content. |
| **AsrOfficeChildProcessAudited** | An attack surface reduction rule detected an Office application spawning a child process. |
| **AsrObfuscatedScriptBlocked** | An attack surface reduction rule blocked the execution of scripts that appear obfuscated. |
| **AsrOfficeChildProcessBlocked** | An attack surface reduction rule blocked an Office application from creating child processes. |
| **AsrOfficeCommAppChildProcessBlocked** | An attack surface reduction rule blocked an Office communication app from spawning a child process. |
| **AsrOfficeCommAppChildProcessAudited** | An attack surface reduction rule detected an Office communication app attempting to spawn a child process. |
| **AsrObfuscatedScriptAudited** | An attack surface reduction rule detected the execution of scripts that appear obfuscated. |
| **AsrExecutableOfficeContentAudited** | An attack surface reduction rule detected an Office application creating executable content. |
| **AsrExecutableEmailContentBlocked** | An attack surface reduction rule blocked executable content from an email client and or webmail. |
| **AsrExecutableOfficeContentBlocked** | An attack surface reduction rule blocked an Office application from creating executable content. |
| **AsrLsassCredentialTheftBlocked** | An attack surface reduction rule blocked possible credential theft from lsass.exe. |
| **AsrLsassCredentialTheftAudited** | An attack surface reduction rule detected possible credential theft from lsass.exe. |
| **AsrPsexecWmiChildProcessBlocked** | An attack surface reduction rule blocked the use of PsExec or WMI commands to spawn a child process. |
| **AsrPsexecWmiChildProcessAudited** | An attack surface reduction rule detected the use of PsExec or WMI commands to spawn a child process. |
| **AsrRansomwareAudited** | An attack surface reduction rule detected ransomware activity. |
| **AsrScriptExecutableDownloadAudited** | An attack surface reduction rule detected JavaScript or VBScript code launching downloaded executable content. |
| **AsrRansomwareBlocked** | An attack surface reduction rule blocked ransomware activity. |
| **AsrPersistenceThroughWmiBlocked** | An attack surface reduction rule blocked an attempt to establish persistence through WMI event subscription. |
| **AsrOfficeMacroWin32ApiCallsBlocked** | An attack surface reduction rule blocked Win32 API calls from Office macros. |
| **AsrOfficeMacroWin32ApiCallsAudited** | An attack surface reduction rule detected Win32 API calls from Office macros. |
| **AsrOfficeProcessInjectionAudited** | An attack surface reduction rule detected an Office application injecting code into other processes. |
| **AsrPersistenceThroughWmiAudited** | An attack surface reduction rule detected an attempt to establish persistence through WMI event subscription. |
| **AsrOfficeProcessInjectionBlocked** | An attack surface reduction rule blocked an Office application from injecting code into other processes. |

### Examples:

### Get the list the USB devices attached to a device in the past week
```
//Get the list the USB devices attached to a device in the past week
let myDevice = "<insert your device ID>";
DeviceEvents 
| where ActionType == "UsbDriveMount" and Timestamp > ago(7d) and DeviceId == myDevice
| extend ProductName = todynamic(AdditionalFields)["ProductName"], SerialNumber = todynamic(AdditionalFields)["SerialNumber"], 
Manufacturer = todynamic(AdditionalFields)["Manufacturer"], Volume = todynamic(AdditionalFields)["Volume"]
| summarize lastInsert = max(Timestamp) by tostring(ProductName), tostring(SerialNumber), tostring(Manufacturer), tostring(Volume) 
```

### Get antivirus scan events, including completed and cancelled scans on a device in the past week
```
// Get antivirus scan events, including completed and cancelled scans
let myDevice = "<insert your device ID>";
DeviceEvents 
| where ActionType startswith "AntivirusScan"  and Timestamp > ago(7d) and DeviceId == myDevice
| extend ScanDesc = parse_json(AdditionalFields)
|project Timestamp, DeviceName, ActionType, Domain = ScanDesc.Domain, ScanId= ScanDesc.ScanId, User = ScanDesc.User, ScanParametersIndex = ScanDesc.ScanParametersIndex, ScanTypeIndex = ScanDesc.ScanTypeIndex
```


## Table: DeviceFileCertificateInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicefilecertificateinfo-table?view=o365-worldwide)
**Description:** Certificate information of signed files obtained from certificate verification events on endpoints

### Table Schema:
| Field | Description |
| --- | --- |
| **CrlDistributionPointUrls** | JSON array listing the URLs of network shares that contain certificates and certificate revocation lists (CRLs) |
| **CertificateCreationTime** | Date and time the certificate was created |
| **IssuerHash** | Unique hash value identifying issuing certificate authority (CA) |
| **CertificateSerialNumber** | Identifier for the certificate that is unique to the issuing certificate authority (CA) |
| **CertificateExpirationTime** | Date and time the certificate is set to expire |
| **IsRootSignerMicrosoft** | Indicates whether the signer of the root certificate is Microsoft |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **CertificateCountersignatureTime** | Date and time the certificate was countersigned |
| **IsTrusted** | Indicates whether the file is trusted based on the results of the WinVerifyTrust function, which checks for unknown root certificate information, invalid signatures, revoked certificates, and other questionable attributes |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **Timestamp** | Date and time when the record was generated |
| **DeviceId** | Unique identifier for the device in the service |
| **IsSigned** | Indicates whether the file is signed |
| **SignerHash** | Unique hash value identifying the signer |
| **Issuer** | Information about the issuing certificate authority (CA) |
| **SignatureType** | Indicates whether signature information was read as embedded content in the file itself or read from an external catalog file |
| **Signer** | Information about the signer of the file |

### Examples:

### Find files with Elliptic Curve Cryptography (ECC) certificates showing Microsoft as the root signer but the incorrect signer name
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


## Table: DeviceFileEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicefileevents-table?view=o365-worldwide)
**Description:** File creation, modification, and other file system events

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **IsAzureInfoProtectionApplied** | Indicates whether the file is encrypted by Azure Information Protection |
| **SensitivitySubLabel** | Sublabel applied to an email, file, or other content to classify it for information protection; sensitivity sublabels are grouped under sensitivity labels but are treated independently |
| **SensitivityLabel** | Label applied to an email, file, or other content to classify it for information protection |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **ShareName** | Name of shared folder containing the file |
| **RequestSourcePort** | Source port on the remote device that initiated the activity |
| **RequestSourceIP** | IPv4 or IPv6 address of the remote device that initiated the activity |
| **RequestProtocol** | Network protocol, if applicable, used to initiate the activity: Unknown, Local, SMB, or NFS |
| **RequestAccountSid** | Security Identifier (SID) of the account used to remotely initiate the activity |
| **RequestAccountDomain** | Domain of the account used to remotely initiate the activity |
| **RequestAccountName** | User name of account used to remotely initiate the activity |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **FileOriginUrl** | URL where the file was downloaded from |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **PreviousFolderPath** | Original folder containing the file before the recorded action was applied |
| **FileOriginIP** | IP address where the file was downloaded from |
| **FileOriginReferrerUrl** | URL of the web page that links to the downloaded file |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **ActionType** | Type of activity that triggered the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **FileSize** | Size of the file in bytes |
| **PreviousFileName** | Original name of the file that was renamed as a result of the action |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **FileModified** | A file on the device was modified. |
| **FileRenamed** | A file on the device was renamed. |
| **FileCreated** | A file was created on the device. |
| **FileDeleted** | A file was deleted. |

### Examples:

### Get the list of sensitive files that were uploaded to a cloud app or service
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

### Track when a specific file has been copied or moved 
```
let myFile = '<file SHA1>';
DeviceFileEvents
| where SHA1 == myFile and ActionType == 'FileCreated'
| limit 100
```


## Table: DeviceImageLoadEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceimageloadevents-table?view=o365-worldwide)
**Description:** DLL loading events

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **FileSize** | Size of the file in bytes |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ImageLoaded** | A dynamic link library (DLL) was loaded. |

## Table: DeviceInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceinfo-table?view=o365-worldwide)
**Description:** Machine information, including OS information

### Table Schema:
| Field | Description |
| --- | --- |
| **Vendor** | Name of the product vendor or manufacturer; only available if device discovery finds enough information about this attribute |
| **Model** | Model name or number of the product from the vendor or manufacturer; only available if device discovery finds enough information about this attribute |
| **OSVersionInfo** | Additional information about the OS version, such as the popular name, code name, or version number |
| **OSDistribution** | Distribution of the OS platform, such as Ubuntu or RedHat for Linux platforms |
| **DeviceCategory** | Broader classification that groups certain device types under the following categories: Endpoint, Network device, IoT, Unknown |
| **AdditionalFields** | Additional information about the entity or event |
| **DeviceSubtype** | Additional modifier for certain types of devices; for example, a mobile device can be a tablet or a smartphone; only available if device discovery finds enough information about this attribute |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **ExclusionReason** | The reason for the device being excluded |
| **IsExcluded** | Determines if the device is excluded from different views and reports in the portal |
| **AssetValue** | Priority or value assigned to the device in relation to its importance in computing the organization's exposure score; can be: Low, Normal (Default), High |
| **ExposureLevel** | The device's level of vulnerability to exploitation based on its exposure score; can be: Low, Medium, High |
| **MergedToDeviceId** | The most recent device ID assigned to a device  |
| **MergedDeviceIds** | Previous device IDs that have been assigned to the same device. |
| **SensorHealthState** | Indicates health of the deviceâ€™s EDR sensor, if onboarded to Microsoft Defender For Endpoint |
| **IsInternetFacing** | Indicates whether the device is internet-facing |
| **OnboardingStatus** | Indicates whether the device is currently onboarded or not to Microsoft Defender For Endpoint or if the device is not supported |
| **OSArchitecture** | Architecture of the operating system running on the machine |
| **PublicIP** | Public IP address used by the onboarded machine to connect to the Windows Defender ATP service. This could be the IP address of the machine itself, a NAT device, or a proxy |
| **OSBuild** | Build version of the operating system running on the machine |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **ClientVersion** | Version of the endpoint agent or sensor running on the machine |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **OSVersion** | Version of the operating system running on the machine |
| **RegistryDeviceTag** | Device tag added through the registry |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **MachineGroup** | Machine group of the machine. This group is used by role-based access control to determine access to the machine |
| **JoinType** | The device's Azure Active Directory join type |
| **IsAzureADJoined** | Boolean indicator of whether machine is joined to the Azure Active Directory |
| **LoggedOnUsers** | List of all users that are logged on the machine at the time of the event in JSON array format |
| **AadDeviceId** | Unique identifier for the device in Azure AD |

### Examples:

### List users that have logged on to a specific device during a specific time period
```
let myDevice = "<insert your device ID>";
DeviceInfo
| where Timestamp between (datetime(2020-05-19) .. datetime(2020-05-20)) and DeviceId == myDevice
| project LoggedOnUsers 
| mvexpand todynamic(LoggedOnUsers) to typeof(string)
| summarize by LoggedOnUsers
```

### List devices running operating systems older than Windows 10
```
//List devices running operating systems older than Windows 10
DeviceInfo 
| where todecimal(OSVersion) < 10 
| summarize by DeviceId, DeviceName, OSVersion, OSPlatform, OSBuild  
```


## Table: DeviceLogonEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicelogonevents-table?view=o365-worldwide)
**Description:** 	Sign-ins and other authentication events

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountName** | User name of the account |
| **Protocol** | Protocol used during the communication |
| **IsLocalAdmin** | Boolean indicator of whether the user is a local administrator on the machine |
| **FailureReason** | Information explaining why the recorded action failed |
| **AccountDomain** | Domain of the account |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **ActionType** | Type of activity that triggered the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **RemoteDeviceName** | Name of the device that performed a remote operation on the affected machine. Depending on the event being reported, this name could be a fully-qualified domain name (FQDN), a NetBIOS name, or a host name without domain information. |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **RemoteIP** | IP address that was being connected to |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **LogonSuccess** | A user successfully logged on to the device. |
| **LogonFailed** | A user attempted to logon to the device but failed. |
| **LogonAttempted** | A user attempted to log on to the device. |

### Examples:

### Get the 10 latest logons performed by accounts within 30 minutes of receiving a known malicious email. Use the logons to check whether the accounts have been compromised.
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

### List authentication events by members of the local administrator group or the built-in administrator account
```
//List authentication events by members of the local administrator group or the built-in administrator account
let myDevice = "<insert your device ID>";
DeviceLogonEvents
| where  IsLocalAdmin == '1'  and Timestamp > ago(7d) and DeviceId == "00d20207bebd88fea19194bd775a372875c7ab1f"
| limit 500
```


## Table: DeviceNetworkEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table?view=o365-worldwide)
**Description:** Network connection and related events

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **RemoteUrl** | URL or fully qualified domain name (FQDN) that was being connected to |
| **RemotePort** | TCP port on the remote device that was being connected to |
| **LocalIP** | IP address assigned to the local machine used during communication |
| **Protocol** | Protocol used during the communication |
| **LocalPort** | TCP port on the local machine used during communication |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **RemoteIP** | IP address that was being connected to |
| **ActionType** | Type of activity that triggered the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **RemoteIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |
| **LocalIPType** | Type of IP address, for example Public, Private, Reserved, Loopback, Teredo, FourToSixMapping, and Broadcast |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ListeningConnectionCreated** | A process has started listening for connections on a certain port. |
| **InboundInternetScanInspected** | An incoming packet from a Microsoft Defender External Attack Surface Management scan was inspected on the device. |
| **InboundConnectionAccepted** | The device accepted a network connection initiated by another device. |
| **SshConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an SSH connection. |
| **SmtpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an SMTP connection. |
| **NetworkSignatureInspected** | A packet content was inspected. |
| **IcmpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an ICMP connection. |
| **ConnectionRequest** | The device initiated a network connection. |
| **ConnectionFound** | An active network connection was found on the device. |
| **ConnectionFailed** | An attempt to establish a network connection from the device failed. |
| **HttpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an HTTP connection. |
| **FtpConnectionInspected** | The deep packet inspection engine in Microsoft Defender for Endpoint inspected an FTP connection. |
| **ConnectionSuccess** | A network connection was successfully established from the device. |

### Examples:

### Find network connections by known Tor clients
```
//Find network connections by known Tor clients
DeviceNetworkEvents  
| where Timestamp > ago(7d) and InitiatingProcessFileName in~ ("tor.exe", "meek-client.exe")
// Returns MD5 hashes of files used by Tor, to enable you to block them.
// We count how prevalent each file is (by devices) and show examples for some of them (up to 5 device names per hash).
| summarize DeviceCount=dcount(DeviceId), DeviceNames=make_set(DeviceName, 5) by InitiatingProcessMD5
| order by DeviceCount desc
```

### Check command lines used to launch PowerShell for strings that indicate download activity
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


## Table: DeviceNetworkInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicenetworkinfo-table?view=o365-worldwide)
**Description:** Network properties of machines, including adapters, IP and MAC addresses, as well as connected networks and domains

### Table Schema:
| Field | Description |
| --- | --- |
| **IPv4Dhcp** | IPv4 address of DHCP server |
| **IPv6Dhcp** | IPv6 address of DHCP server |
| **ConnectedNetworks** | Networks that the adapter is connected to. Each JSON element in the array contains the network name, category (public, private or domain), a description, and a flag indicating if itâ€™s connected publicly to the internet |
| **DnsAddresses** | DNS server addresses in JSON array format |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **NetworkAdapterVendor** | Name of the manufacturer or vendor of the network adapter |
| **DefaultGateways** | Default gateway addresses in JSON array format |
| **IPAddresses** | JSON array containing all the IP addresses assigned to the adapter, along with their respective subnet prefix and the IP class (RFC 1918 & RFC 4291) |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **NetworkAdapterName** | Name of the network adapter |
| **Timestamp** | Date and time when the record was generated |
| **DeviceId** | Unique identifier for the device in the service |
| **NetworkAdapterStatus** | Operational status of the network adapter |
| **TunnelType** | Tunneling protocol, if the interface is used for this purpose, for example 6to4, Teredo, ISATAP, PPTP, SSTP, and SSH |
| **MacAddress** | MAC address of the network adapter |
| **NetworkAdapterType** | Network adapter type |

### Examples:

### List all devices that have been assigned a specific IP address
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


## Table: DeviceProcessEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table?view=o365-worldwide)
**Description:** Process creation and related events

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessLogonId** | Identifier for a logon session of the process that initiated the event. This identifier is unique on the same machine only between restarts. |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessSignerType** | Type of file signer of the process (image file) that initiated the event |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessSignatureStatus** | Information about the signature status of the process (image file) that initiated the event |
| **AdditionalFields** | Additional information about the entity or event |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **FileSize** | Size of the file in bytes |
| **MD5** | MD5 hash of the file that the recorded action was applied to |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **ProcessVersionInfoCompanyName** | Company name from the version information of the newly created process |
| **ProcessVersionInfoInternalFileName** | Internal file name from the version information of the newly created process |
| **ProcessVersionInfoProductVersion** | Product version from the version information of the newly created process |
| **ProcessVersionInfoProductName** | Product name from the version information of the newly created process |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **SHA1** | SHA-1 hash of the file that the recorded action was applied to |
| **FolderPath** | Folder containing the file that the recorded action was applied to |
| **FileName** | Name of the file that the recorded action was applied to |
| **ProcessVersionInfoOriginalFileName** | Original file name from the version information of the newly created process |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **LogonId** | Identifier for a logon session. This identifier is unique on the same machine only between restarts |
| **ProcessCommandLine** | Command line used to create the new process |
| **ProcessId** | Process ID (PID) of the newly created process |
| **ProcessVersionInfoFileDescription** | Description from the version information of the newly created process |
| **ProcessIntegrityLevel** | Integrity level of the newly created process. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet downloaded. These integrity levels influence permissions to resources. |
| **AccountDomain** | Domain of the account |
| **ProcessCreationTime** | Date and time the process was created |
| **ProcessTokenElevation** | Indicates the type of token elevation applied to the newly created process. Possible values: TokenElevationTypeLimited (restricted), TokenElevationTypeDefault (standard), and TokenElevationTypeFull (elevated) |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **ProcessCreated** | A process was launched on the device. |
| **OpenProcess** | The OpenProcess function was called indicating an attempt to open a handle to a local process and potentially manipulate that process. |

### Examples:

### Find PowerShell activities that occur right after receiving an email from a malicious sender
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

### Check process command lines for attempts to clear event logs
```
//Check process command lines for attempts to clear event logs
let myDevice = "<insert your device ID>";
DeviceProcessEvents 
| where DeviceId == myDevice and Timestamp > ago(7d) and ((InitiatingProcessCommandLine contains "wevtutil" and (InitiatingProcessCommandLine contains ' cl ' or InitiatingProcessCommandLine contains ' clear ' or InitiatingProcessCommandLine contains ' clearev ' )) 
or (InitiatingProcessCommandLine contains ' wmic ' and InitiatingProcessCommandLine contains ' cleareventlog '))
```


## Table: DeviceRegistryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceregistryevents-table?view=o365-worldwide)
**Description:** Creation and modification of registry entries

### Table Schema:
| Field | Description |
| --- | --- |
| **InitiatingProcessVersionInfoOriginalFileName** | Original file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoInternalFileName** | Internal file name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessId** | Process ID (PID) of the process that initiated the event |
| **InitiatingProcessVersionInfoFileDescription** | Description from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoProductVersion** | Product version from the version information of the process (image file) responsible for the event |
| **InitiatingProcessFileSize** | Size of the process (image file) that initiated the event |
| **InitiatingProcessFileName** | Name of the process that initiated the event |
| **InitiatingProcessVersionInfoProductName** | Product name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessVersionInfoCompanyName** | Company name from the version information of the process (image file) responsible for the event |
| **InitiatingProcessCommandLine** | Command line used to run the process that initiated the event |
| **InitiatingProcessTokenElevation** | Token type indicating the presence or absence of User Access Control (UAC) privilege elevation applied to the process that initiated the event |
| **InitiatingProcessIntegrityLevel** | Integrity level of the process that initiated the event. Windows assigns integrity levels to processes based on certain characteristics, such as if they were launched from an internet download. These integrity levels influence permissions to resources. |
| **AppGuardContainerId** | Identifier for the virtualized container used by Application Guard to isolate browser activity |
| **ReportId** | Event identifier based on a repeating counter.To identify unique events, this column must be used in conjunction with the DeviceName and Timestamp columns. |
| **InitiatingProcessParentCreationTime** | Date and time when the parent of the process responsible for the event was started |
| **InitiatingProcessFolderPath** | Folder containing the process (image file) that initiated the event |
| **InitiatingProcessCreationTime** | Date and time when the process that initiated the event was started |
| **InitiatingProcessParentFileName** | Name of the parent process that spawned the process responsible for the event |
| **InitiatingProcessParentId** | Process ID (PID) of the parent process that spawned the process responsible for the event |
| **RegistryValueName** | Name of the registry value that the recorded action was applied to |
| **RegistryValueType** | Data type, such as binary or string, of the registry value that the recorded action was applied to |
| **PreviousRegistryKey** | Original registry key before it was modified |
| **RegistryValueData** | Data of the registry value that the recorded action was applied to |
| **RegistryKey** | Registry key that the recorded action was applied to |
| **DeviceId** | Unique identifier for the device in the service |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **PreviousRegistryValueName** | Original name of the registry value before it was modified |
| **InitiatingProcessSHA1** | SHA-1 hash of the process (image file) that initiated the event |
| **InitiatingProcessAccountObjectId** | Azure AD object ID of the user account that ran the process responsible for the event |
| **InitiatingProcessMD5** | MD5 hash of the process (image file) that initiated the event |
| **InitiatingProcessSHA256** | SHA-256 hash of the process (image file) that initiated the event. This field is usually not populated - use the SHA1 column when available. |
| **InitiatingProcessAccountUpn** | User principal name (UPN) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountDomain** | Domain of the account that ran the process responsible for the event |
| **PreviousRegistryValueData** | Original data of the registry value before it was modified |
| **InitiatingProcessAccountSid** | Security Identifier (SID) of the account that ran the process responsible for the event |
| **InitiatingProcessAccountName** | User name of the account that ran the process responsible for the event |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **RegistryValueDeleted** | A registry value was deleted. |
| **RegistryValueSet** | The data for a registry value was modified. |
| **RegistryKeyRenamed** | A registry key was renamed. |
| **RegistryKeyCreated** | A registry key was created. |
| **RegistryKeyDeleted** | A registry key was deleted. |

### Examples:

### Get the list of devices where certain Microsoft Defender ATP capabilities, such as real-time protection, have been turned off
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
    // Where 1 means itâ€™s disabled.
and RegistryValueData has "1" and isnotempty(PreviousRegistryValueData) and Timestamp > ago(7d)
| project Timestamp, ActionType, DeviceId , DeviceName, RegistryKey, RegistryValueName , RegistryValueData,  PreviousRegistryValueData  
```

### Check a specific device for the services set to automatically start with Windows
```
//Check a specific device for the services set to automatically start with Windows
let myDevice = "<insert your device ID>";
DeviceRegistryEvents
| where DeviceId == "35cc086a8bb43808f9586ee890b04a64726a60d6"//myDevice 
    and ActionType in ("RegistryValueSet") 
    and RegistryKey matches regex @"HKEY_LOCAL_MACHINE\\SYSTEM\\.*\\Services\\.*"  
    and RegistryValueName == "Start" and RegistryValueData == "2"
| limit 100
```


## Table: DeviceTvmInfoGathering

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvminfogathering-table?view=o365-worldwide)
**Description:** The DeviceTvmInfoGathering table contains Threat & Vulnerability Management assessment events including the status of various configurations and attack surface area states of devices.

### Table Schema:
| Field | Description |
| --- | --- |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **AdditionalFields** | Additional information about the entity or event |
| **Timestamp** | Date and time when the record was generated |
| **LastSeenTime** | Date and time when the service last saw the device |
| **DeviceId** | Unique identifier for the device in the service |

## Table: DeviceTvmInfoGatheringKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvminfogatheringkb-table?view=o365-worldwide)
**Description:** The DeviceTvmInfoGatheringKB table contains the list of various configuration and attack surface area assessments used by Threat & Vulnerability Management information gathering to assess devices

### Table Schema:
| Field | Description |
| --- | --- |
| **Categories** | List of categories that the information belongs to, in JSON array format |
| **DataStructure** | The data structure of the information gathered |
| **Description** | Description of the information gathered |
| **IgId** | Unique identifier for the piece of information gathered |
| **FieldName** | Name of the field where this information appears in the AdditionalFields column of the DeviceTvmInfoGathering table |

## Table: DeviceTvmSecureConfigurationAssessment

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessment-table?view=o365-worldwide)
**Description:** Threat & Vulnerability Management assessment events, indicating the status of various security configurations on devices

### Table Schema:
| Field | Description |
| --- | --- |
| **IsCompliant** | Indicates whether the configuration or policy is properly configured |
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10) |
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features. |
| **IsExpectedUserImpact** | Indicates whether there will be user impact if the configuration will be applied |
| **Context** | Configuration context data of the machine |
| **IsApplicable** | Indicates whether the configuration or policy is applicable |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **ConfigurationCategory** | Category or grouping to which the configuration belongs |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **Timestamp** | Date and time when the record was generated |

## Table: DeviceTvmSecureConfigurationAssessmentKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsecureconfigurationassessmentkb-table?view=o365-worldwide)
**Description:** Knowledge base of various security configurations used by Threat & Vulnerability Management to assess devices; includes mappings to various standards and benchmarks

### Table Schema:
| Field | Description |
| --- | --- |
| **ConfigurationSubcategory** | Subcategory or subgrouping to which the configuration belongs. In many cases, this describes specific capabilities or features. |
| **ConfigurationCategory** | Category or grouping to which the configuration belongs |
| **ConfigurationBenchmarks** | List of industry benchmarks recommending the same or similar configuration |
| **RemediationOptions** | Recommended actions to reduce or address any associated risks |
| **Tags** | Labels representing various attributes used to identify or categorize a security configuration |
| **ConfigurationImpact** | Rated impact of the configuration to the overall configuration score (1-10) |
| **ConfigurationId** | Unique identifier for a specific configuration |
| **ConfigurationName** | Display name of the configuration |
| **RiskDescription** | Description of any associated risks |
| **ConfigurationDescription** | Description of the configuration |

## Table: DeviceTvmSoftwareEvidenceBeta

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareevidencebeta-table?view=o365-worldwide)
**Description:** Evidence indicating the existence of a software on a device based on registry paths, disk paths, or both.

### Table Schema:
| Field | Description |
| --- | --- |
| **RegistryPaths** | Registry paths on which evidence indicating the existence of a software on a device was detected |
| **DiskPaths** | Disk paths on which file level evidence indicating the existence of a software on a device was detected |
| **LastSeenTime** | Date and time when the service last saw the device |
| **SoftwareVersion** | Version number of the software product |
| **DeviceId** | Unique identifier for the device in the service |
| **SoftwareVendor** | Name of the software vendor |
| **SoftwareName** | Name of the software product |

## Table: DeviceTvmSoftwareInventory

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwareinventory-table?view=o365-worldwide)
**Description:** Inventory of software installed on devices, including their version information and end-of-support status

### Table Schema:
| Field | Description |
| --- | --- |
| **SoftwareVersion** | Version number of the software product |
| **SoftwareName** | Name of the software product |
| **EndOfSupportStatus** | Indicates the lifecycle stage of the software product relative to its specified end-of-support (EOS) or end-of-life (EOL) date |
| **ProductCodeCpe** | The standard Common Platform Enumeration (CPE) name of the software product version |
| **EndOfSupportDate** | End-of-support (EOS) or end-of-life (EOL) date of the software product |
| **SoftwareVendor** | Name of the software vendor |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **OSArchitecture** | Architecture of the operating system running on the machine |
| **OSVersion** | Version of the operating system running on the machine |

### Examples:

### List software titles which are not supported anymore and the number of devices with these titles
```
//List software titles which are not supported anymore
DeviceTvmSoftwareInventory
| where EndOfSupportStatus == 'EOS Software'
| summarize dcount(DeviceId ) by SoftwareName
```


## Table: DeviceTvmSoftwareVulnerabilities

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwarevulnerabilities-table?view=o365-worldwide)
**Description:** Software vulnerabilities found on devices and the list of available security updates that address each vulnerability

### Table Schema:
| Field | Description |
| --- | --- |
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape |
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system |
| **SoftwareVersion** | Version number of the software product |
| **RecommendedSecurityUpdate** | Name or description of the security update provided by the software vendor to address the vulnerability |
| **CveMitigationStatus** | Indicates the status of the workaround mitigation for the CVE on this device (possible values: applied, not applied, partially applied, pending reboot) |
| **CveTags** | Array of tags relevant to the CVE; example: ZeroDay, NoSecurityUpdate |
| **RecommendedSecurityUpdateId** | Identifier of the applicable security updates or identifier for the corresponding guidance or knowledge base (KB) articles |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **DeviceId** | Unique identifier for the device in the service |
| **OSVersion** | Version of the operating system running on the machine |
| **SoftwareName** | Name of the software product |
| **SoftwareVendor** | Name of the software vendor |
| **OSArchitecture** | Architecture of the operating system running on the machine |

### Examples:

### List devices affected by a specific vulnerability
```
DeviceTvmSoftwareVulnerabilities
| where CveId == 'CVE-2020-0791'
| limit 100
```


## Table: DeviceTvmSoftwareVulnerabilitiesKB

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicetvmsoftwarevulnerabilitieskb-table?view=o365-worldwide)
**Description:** Knowledge base of publicly disclosed vulnerabilities, including whether exploit code is publicly available

### Table Schema:
| Field | Description |
| --- | --- |
| **PublishedDate** | Date vulnerability was disclosed to the public |
| **LastModifiedTime** | Date and time the item or related metadata was last modified |
| **AffectedSoftware** | List of all software products affected by the vulnerability |
| **VulnerabilityDescription** | Description of the vulnerability and associated risks |
| **CvssScore** | Severity score assigned to the security vulnerability under the Common Vulnerability Scoring System (CVSS) |
| **CveId** | Unique identifier assigned to the security vulnerability under the Common Vulnerabilities and Exposures (CVE) system |
| **VulnerabilitySeverityLevel** | Severity level assigned to the security vulnerability based on the CVSS score and dynamic factors influenced by the threat landscape |
| **IsExploitAvailable** | Indicates whether exploit code for the vulnerability is publicly available |

### Examples:

### Get all information on a specific vulnerability
```
DeviceTvmSoftwareVulnerabilitiesKB
| where CveId == 'CVE-2020-0791'
```

### List vulnerabilities that have an available exploit and were publishde in the last week.
```
//List vulnerabilities that have an available exploit and were published in the last week.
DeviceTvmSoftwareVulnerabilitiesKB
| where IsExploitAvailable == True and PublishedDate > ago(7d)
| limit 100
```


## Table: EmailAttachmentInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailattachmentinfo-table?view=o365-worldwide)
**Description:** Information about files attached to Office 365 emails

### Table Schema:
| Field | Description |
| --- | --- |
| **FileSize** | Size of the file in bytes |
| **SHA256** | SHA-256 of the file that the recorded action was applied to |
| **FileType** | File extension type |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **ReportId** | Unique identifier for the event |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **ThreatNames** | Detection name for malware or other threats found |
| **FileName** | Name of the file that the recorded action was applied to |
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **Timestamp** | Date and time when the record was generated |
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname |
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **SenderObjectId** | Unique identifier for the senderâ€™s account in Azure AD |

### Examples:

### Find the appearance of files sent by a specific malicious sender on devices on the network
```
// Finds the first appearance of files sent by a malicious sender in your organization
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

### List all email messages with attachments that were sent to external domains
```
EmailEvents
| where EmailDirection == "Outbound" and AttachmentCount > 0
| join EmailAttachmentInfo on NetworkMessageId 
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, FileName, AttachmentCount 
| take 100
```


## Table: EmailEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailevents-table?view=o365-worldwide)
**Description:** Office 365 email events, including email delivery and blocking events

### Table Schema:
| Field | Description |
| --- | --- |
| **AuthenticationDetails** | List of pass or fail verdicts by email authentication protocols like DMARC, DKIM, SPF or a combination of multiple authentication types (CompAuth) |
| **EmailActionPolicyGuid** | Unique identifier for the policy that determined the final mail action |
| **UrlCount** | Number of embedded URLs in the email |
| **AttachmentCount** | Number of attachments in the email |
| **EmailActionPolicy** | Action policy that took effect: Antispam high-confidence, Antispam, Antispam bulk mail, Antispam phishing, Anti-phishing domain impersonation, Anti-phishing user impersonation, Anti-phishing spoof, Anti-phishing graph impersonation, Antimalware Safe Attachments, Enterprise Transport Rules (ETR) |
| **ConfidenceLevel** | List of confidence levels of any spam or phishing verdicts. For spam, this column shows the spam confidence level (SCL), indicating if the email was skipped (-1), found to be not spam (0,1), found to be spam with moderate confidence (5,6), or found to be spam with high confidence (9). For phishing, this column displays whether the confidence level is "High" or "Low". |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **EmailAction** | Final action taken on the email based on filter verdict, policies, and user actions:  Move message to junk mail folder, Add X-header, Modify subject, Redirect message, Delete message, send to quarantine, No action taken, Bcc message |
| **BulkComplaintLevel** | Threshold assigned to email from bulk mailers, a high bulk complain level (BCL) means the email is more likely to generate complaints, and thus more likely to be spam |
| **EmailLanguage** | Detected language of the email content |
| **AdditionalFields** | Additional information about the entity or event |
| **ReportId** | Unique identifier for the event |
| **LatestDeliveryAction** | Last known action attempted on an email by the service or by an admin through manual remediation.  |
| **LatestDeliveryLocation** | Last known location of the email. |
| **UserLevelPolicy** | End user mailbox policy that triggered the action taken on the email |
| **OrgLevelAction** | Action taken on the email in response to matches to a policy defined at the organizational level |
| **Connectors** | Custom instructions that define organizational mail flow and how the email was routed |
| **UserLevelAction** | Action taken on the email in response to matches to a mailbox policy defined by the recipient |
| **OrgLevelPolicy** | Organizational policy that triggered the action taken on the email |
| **ThreatNames** | Detection name for malware or other threats found |
| **SenderObjectId** | Unique identifier for the senderâ€™s account in Azure AD |
| **SenderDisplayName** | Name of the sender displayed in the address book, typically a combination of a given or first name, a middle initial, and a last name or surname |
| **SenderFromDomain** | Sender domain in the FROM header, which is visible to email recipients on their email clients |
| **SenderMailFromDomain** | Sender domain in the MAIL FROM header, also known as the envelope sender or the Return-Path address |
| **SenderFromAddress** | Sender email address in the FROM header, which is visible to email recipients on their email clients |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **Timestamp** | Date and time when the record was generated |
| **SenderMailFromAddress** | Sender email address in the MAIL FROM header, also known as the envelope sender or the Return-Path address |
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system |
| **SenderIPv4** | IPv4 address of the last detected mail server that relayed the message |
| **DeliveryAction** | Delivery action of the email: Delivered, Junked, Blocked, or Replaced |
| **EmailDirection** | Direction of the email relative to your network:  Inbound, Outbound, Intra-org |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items |
| **EmailClusterId** | Identifier for the group of similar emails clustered based on heuristic analysis of their contents |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **SenderIPv6** | IPv6 address of the last detected mail server that relayed the message |
| **Subject** | Subject of the email |
| **RecipientObjectId** | Unique identifier for the email recipient in Azure AD |

### Examples:

### Get the number of phishing emails from the top ten sender domains
```
//Get the number of phishing emails from the top ten sender domains
EmailEvents
| where ThreatTypes has "Phish"
| summarize Count = count() by SenderFromDomain
| top 10 by Count
```

### List all email messages found containing malware
```
EmailEvents
| where ThreatTypes has "Malware"
| limit 500
```


## Table: EmailPostDeliveryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailpostdeliveryevents-table?view=o365-worldwide)
**Description:** Security events that occur post-delivery, after Office 365 has delivered an email message to the recipient mailbox

### Table Schema:
| Field | Description |
| --- | --- |
| **DeliveryLocation** | Location where the email was delivered: Inbox/Folder, On-premises/External, Junk, Quarantine, Failed, Dropped, Deleted items |
| **RecipientEmailAddress** | Email address of the recipient, or email address of the recipient after distribution list expansion |
| **ActionResult** | Result of the action |
| **ReportId** | Unique identifier for the event |
| **DetectionMethods** | Methods used to detect malware, phishing, or other threats found in the email |
| **ThreatTypes** | Verdict from the email filtering stack on whether the email contains malware, phishing, or other threats |
| **InternetMessageId** | Public-facing identifier for the email that is set by the sending email system |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **Timestamp** | Date and time when the record was generated |
| **ActionTrigger** | Indicates whether an action was triggered by an administrator (manually or through approval of a pending automated action), or by some special mechanism, such as a ZAP or Dynamic Delivery |
| **ActionType** | Type of activity that triggered the event |
| **Action** | Action taken on the entity |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **Phish ZAP** | Zero-hour auto purge (ZAP) took action on a phishing email after delivery. |
| **Spam ZAP** | Zero-hour auto purge (ZAP) took action on spam email after delivery. |
| **Malware ZAP** | Zero-hour auto purge (ZAP) took action on an email message found containing malware after delivery. |
| **Manual Remediation** | An administrator manually took action on an email message after it was delivered to the user mailbox. This includes actions taken manually through Threat Explorer or approvals of automated investigation and response (AIR) actions. |

### Examples:

### Find unremediated emails that were identified as phishing after delivery
```
EmailPostDeliveryEvents
| where ActionType == 'Phish ZAP' and ActionResult == 'Error'
| join EmailEvents on NetworkMessageId, RecipientEmailAddress 
```

### List all actions taken or approved by administrators manually on emails after delivery
```
EmailPostDeliveryEvents
| where ActionTrigger == 'AdminAction'
| limit 100
```

### Get detailed processing information up until post-delivery of an email with a specific subject from a particular sender
```
let mySender = "<insert sender email address>";
let subject = "<insert email subject>";
EmailEvents
| where SenderFromAddress == mySender and Subject == subject
| join EmailPostDeliveryEvents on NetworkMessageId, RecipientEmailAddress
```


## Table: EmailUrlInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-emailurlinfo-table?view=o365-worldwide)
**Description:** Information about URLs on Office 365 emails

### Table Schema:
| Field | Description |
| --- | --- |
| **UrlDomain** | Domain name or host name of the URL |
| **UrlLocation** | Indicates which part of the email the URL is located |
| **ReportId** | Unique identifier for the event |
| **Timestamp** | Date and time when the record was generated |
| **NetworkMessageId** | Unique identifier for the email, generated by Office 365 |
| **Url** | Full Url from email |

### Examples:

### List all URLs in the body of a specific email
```
let myEmailId = "<insert your email NetworkMessageId>";
EmailEvents
| where NetworkMessageId == myEmailId
| join EmailUrlInfo on NetworkMessageId
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, NetworkMessageId, Url, UrlCount
```


## Table: IdentityDirectoryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitydirectoryevents-table?view=o365-worldwide)
**Description:** Events involving a domain controller or a directory service, such as Active Directory (AD ) or Azure AD

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountSid** | Security Identifier (SID) of the account |
| **IPAddress** | IP address assigned to the device during communication |
| **ReportId** | Unique identifier for the event |
| **AdditionalFields** | Additional information about the entity or event |
| **ISP** | Internet service provider associated with  the IP address |
| **Port** | TCP port used during communication |
| **Location** | City, country, or other geographic location associated with the event |
| **AccountDomain** | Domain of the account |
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **Application** | Application that performed the recorded action |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **Protocol** | Protocol used during the communication |
| **AccountName** | User name of the account |
| **DestinationPort** | Destination port of the activity |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **Security Principal deleted changed** | Account was deleted/restored (both user and computer). |
| **Security Principal created** | Account was created (both user and computer). |
| **Security Principal Display Name changed** | Account display name was changed from X to Y. |
| **Security Principal Path changed** | Account Distinguished name was changed from X to Y. |
| **Security Principal Name changed** | Account name attribute was changed. |
| **Group Membership changed** | User was added/removed, to/from a group, by another user or by themselves. |
| **Directory Service replication** | User tried to replicate the directory service. |
| **Potential lateral movement path identified** | Identified potential lateral movement path to a sensitive user. |
| **Private Data Retrieval** | User attempted/succeeded to query private data using LSARPC protocol. |
| **PowerShell execution** | User attempted to remotely execute a PowerShell command. |
| **User Manager changed** | User's manager attribute was changed. |
| **User Mail changed** | Users email attribute was changed. |
| **User Phone Number changed** | User's phone number attribute was changed. |
| **Wmi execution** | User attempted to remotely execute a WMI method. |
| **User Title changed** | User's title attribute was changed. |
| **Service creation** | User attempted to remotely create a specific service to a remote machine. |
| **Security Principal Sam Name changed** | SAM name changed (SAM is the logon name used to support clients and servers running earlier versions of the operating system). |
| **SMB session** | User attempted to enumerate all users with open SMB sessions on the domain controllers. |
| **Task scheduling** | User tried to remotely schedule X task to a remote machine. |
| **SmbFileCopy** | User copied files using SMB. |
| **Account expired** | Date when the account expires. |
| **Account Display Name changed** | User's display name was changed. |
| **Account Expiry Time changed** | Change to the date when the account expires. |
| **Account Name changed** | User's name was changed. |
| **Account Locked changed** | Change to the date when the account expires. |
| **Account Constrained Delegation State changed** | The account state is now enabled or disabled for delegation. |
| **Account Constrained Delegation SPNs changed** | Constrained delegation restricts the services to which the specified server can act on behalf of the user. |
| **Account Delegation changed** | The account state is now enabled or disabled for delegation. |
| **Account Disabled changed** | Indicates whether an account is disabled or enabled. |
| **Account Deleted changed** | User account was deleted. |
| **Account Supported Encryption Types changed** | Kerberos supported encryption types were changed(types: Des, AES 129, AES 256). |
| **Account Smart Card Required changed** | Account changes to require users to log on to a device using a smart card. |
| **Account Upn Name changed** | User's principle name was changed. |
| **Device Operating System changed** | An operating system attribute was changed. |
| **Device Account Created** | A new device account was created. |
| **Account Password expired** | User's password expired. |
| **Account Password changed** | User changed their password. |
| **Account Password Never Expires changed** | User's password changed to never expire. |
| **Account Path changed** | User Distinguished name was changed from X to Y. |
| **Account Password Not Required changed** | User account was changed allow logging in with a blank password. |

### Examples:

### Find the latest password change event for a specific account
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

### List changes made to a specific group
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


## Table: IdentityInfo

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityinfo-table?view=o365-worldwide)
**Description:** Account information from various sources, including Azure Active Directory

### Table Schema:
| Field | Description |
| --- | --- |
| **AccountDomain** | Domain of the account |
| **EmailAddress** | SMTP address of the account |
| **JobTitle** | Job title of the account user |
| **AccountName** | User name of the account |
| **Country** | Country/Region where the account user is located |
| **IsAccountEnabled** | Indicates whether the account is enabled or not |
| **SipProxyAddress** | Voice of over IP (VOIP) session initiation protocol (SIP) address of the account |
| **City** | City where the client IP address is geolocated |
| **OnPremSid** | On-premises security identifier (SID) of the account |
| **CloudSid** | Cloud security identifier of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **Department** | Name of the department that the account user belongs to |
| **GivenName** | Given name or first name of the account user |
| **Surname** | Surname, family name, or last name of the account user |

### Examples:

### List all users in a specific department
```
let MyDepartment= "<insert your department>";
IdentityInfo 
| where Department == MyDepartment
| summarize by AccountObjectId, AccountUpn 
```

### List all users located in a particular country
```
let MyCountry= "<insert your contry>";
IdentityInfo 
| where Country  == MyCountry
| summarize by AccountObjectId, AccountUpn 
```


## Table: IdentityLogonEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identitylogonevents-table?view=o365-worldwide)
**Description:** Authentication events recorded by Active Directory and other Microsoft online services

### Table Schema:
| Field | Description |
| --- | --- |
| **Port** | TCP port used during communication |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |
| **DeviceType** | Type of device based on purpose and functionality, such as network device, workstation, server, mobile, gaming console, or printer |
| **OSPlatform** | Platform of the operating system running on the device. This indicates specific operating systems, including variations within the same family, such as Windows 10 and Windows 7 |
| **IPAddress** | IP address assigned to the device during communication |
| **DestinationPort** | Destination port of the activity |
| **ISP** | Internet service provider associated with  the IP address |
| **ReportId** | Unique identifier for the event |
| **AdditionalFields** | Additional information about the entity or event |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **Location** | City, country, or other geographic location associated with the event |
| **LogonType** | Type of logon session, specifically interactive, remote interactive (RDP), network, batch, and service |
| **Protocol** | Protocol used during the communication |
| **FailureReason** | Information explaining why the recorded action failed |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **Application** | Application that performed the recorded action |
| **AccountName** | User name of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **AccountDomain** | Domain of the account |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountSid** | Security Identifier (SID) of the account |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **LogonSuccess** | A user successfully logged on to the device. |
| **LogonFailed** | A user attempted to logon to the device but failed. |

### Examples:

### Find LDAP authentication attempts using cleartext passwords
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


## Table: IdentityQueryEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-identityqueryevents-table?view=o365-worldwide)
**Description:** Query activities performed against Active Directory objects, such as users, groups, devices, and domains

### Table Schema:
| Field | Description |
| --- | --- |
| **DestinationDeviceName** | Name of the device running the server application that processed the recorded action |
| **DestinationIPAddress** | IP address of the device running the server application that processed the recorded action |
| **DestinationPort** | Destination port of the activity |
| **DeviceName** | Fully qualified domain name (FQDN) of the device |
| **IPAddress** | IP address assigned to the device during communication |
| **Port** | TCP port used during communication |
| **Location** | City, country, or other geographic location associated with the event |
| **ReportId** | Unique identifier for the event |
| **AdditionalFields** | Additional information about the entity or event |
| **TargetDeviceName** | Fully qualified domain name (FQDN) of the device that the recorded action was applied to |
| **TargetAccountUpn** | User principal name (UPN) of the account that the recorded action was applied to |
| **TargetAccountDisplayName** | Display name of the account that the recorded action was applied to |
| **AccountDisplayName** | Name displayed in the address book entry for the account user. This is usually a combination of the given name, middle initial, and surname of the user. |
| **QueryType** | Type of the query |
| **QueryTarget** | User, group, domain, or any other entity being queried |
| **Query** | String used to run the query |
| **Timestamp** | Date and time when the record was generated |
| **ActionType** | Type of activity that triggered the event |
| **Application** | Application that performed the recorded action |
| **AccountUpn** | User principal name (UPN) of the account |
| **AccountSid** | Security Identifier (SID) of the account |
| **AccountObjectId** | Unique identifier for the account in Azure AD |
| **Protocol** | Protocol used during the communication |
| **AccountName** | User name of the account |
| **AccountDomain** | Domain of the account |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **LdapQuery** | An LDAP query was performed. |
| **SAMR query** | A SAMR query was performed. |
| **DNS query** | Type of query user performed against the domain controller (AXFR, TXT, MX, NS, SRV, ANY, DNSKEY) |
| **LDAP query** | An LDAP query was performed. |

### Examples:

### Find use of net.exe to send SAMR queries to Active Directory
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


## Table: UrlClickEvents

[Link to Microsoft](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-urlclickevents-table?view=o365-worldwide)
**Description:** Events involving URLs clicked, selected, or requested on Microsoft Defender for Office 365

### Table Schema:
| Field | Description |
| --- | --- |
| **IPAddress** | IP address assigned to the device during communication |
| **DetectionMethods** | Methods used to detect whether the URL contains or leads to malware, phishing, or other threats |
| **ThreatTypes** | Verdict on whether the URL leads to malware, phishing, or other threats |
| **ReportId** | Unique identifier for the event |
| **UrlChain** | List of URLs in the redirection chain |
| **IsClickedThrough** | Indicates whether the user was able to click through to the original URL or not |
| **ActionType** | Type of activity that triggered the event |
| **Url** | URL that was clicked |
| **Timestamp** | Date and time when the record was generated |
| **NetworkMessageId** | Unique identifier for the email from which the URL was clicked |
| **Workload** | Information about the workload from which the URL originated from |
| **AccountUpn** | User principal name (UPN) of the account |

### ActionTypes:
| ActionType | Description |
| --- | --- |
| **UrlErrorPage** | The URL the user clicked showed an error page. |
| **UrlScanInProgress** | The URL the user clicked is being scanned by Safe Links. |
| **ClickBlockedByTenantPolicy** | The user was blocked from navigating to the URL by a tenant policy. |
| **ClickAllowed** | The user was allowed to navigate to the URL. |
| **ClickBlocked** | The user was blocked from navigating to the URL. |


