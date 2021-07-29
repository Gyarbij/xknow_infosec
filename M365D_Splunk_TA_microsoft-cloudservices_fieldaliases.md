# Improved Field naming in Splunk_TA_microsoft-cloudservices for Azure Eventhub data containing Microsoft 365 Defender events

## Using a fixing SPL macro
```
[fix-mde-rawdata]
definition = | eval IngestedTime=strftime(_time,"%Y-%m-%d %H:%M:%S")\
| spath body.records output=records\
| mvexpand records\
| spath input=records time output=EventHubTime\
| spath input=records category output=category\
| spath input=records tenantId output=tenantId\
| eval EventHubTime=strftime(strptime(EventHubTime,"%Y-%m-%dT%H:%M:%S.%6Q"),"%Y-%m-%d %H:%M:%S")\
| spath input=records properties output=properties\
| mvexpand properties\
| spath input=properties Timestamp output=DetectedTime\
| eval DetectedTime=strftime(strptime(DetectedTime,"%Y-%m-%dT%H:%M:%S.%6Q"),"%Y-%m-%d %H:%M:%S")\
| spath input=properties
iseval = 0
```
Run your SPL with macro fixing the Eventhub data during search-time:
```
index=<your_search> sourcetype=mscs:azure:eventhub
`fix-mde-rawdata`
| table _time TimeIngested TimeDetected tenantId Level category correlationId durationMs operationName operationVersion AadDeviceId AccountDomain AccountName AccountObjectId AccountSid AccountUpn ActionType AdditionalFields AlertId AppGuardContainerId AttackTechniques Category CertificateCountersignatureTime CertificateCreationTime CertificateExpirationTime CertificateSerialNumber ClientVersion ConnectedNetworks CrlDistributionPointUrls DefaultGateways DeviceId DeviceName DeviceObjectId DnsAddresses FailureReason FileName FileOriginIP FileOriginReferrerUrl FileOriginUrl as FolderPath IPAddresses IPv4Dhcp IPv6Dhcp InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessCreationTime InitiatingProcessFileName InitiatingProcessFileSize InitiatingProcessFolderPath InitiatingProcessId InitiatingProcessIntegrityLevel InitiatingProcessLogonId InitiatingProcessMD5 InitiatingProcessParentCreationTime InitiatingProcessParentFileName InitiatingProcessParentId InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessSignatureStatus InitiatingProcessSignerType InitiatingProcessTokenElevation InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion IsAzureADJoined IsAzureInfoProtectionApplied IsLocalAdmin IsRootSignerMicrosoft IsSigned IsTrusted Issuer IssuerHash LocalIP LocalIPType LocalPort LoggedOnUsers LogonId LogonType MD5 MacAddress MachineGroup MitreTechniques NetworkAdapterName NetworkAdapterStatus NetworkAdapterType OSArchitecture OSBuild OSPlatform OSVersion OnboardingStatus PreviousFileName PreviousFolderPath PreviousRegistryKey PreviousRegistryValueData PreviousRegistryValueName ProcessCommandLine ProcessCreationTime ProcessId ProcessIntegrityLevel ProcessTokenElevation ProcessVersionInfoCompanyName ProcessVersionInfoFileDescription ProcessVersionInfoInternalFileName ProcessVersionInfoOriginalFileName ProcessVersionInfoProductName ProcessVersionInfoProductVersion Protocol PublicIP RegistryDeviceTag RegistryKey RegistryValueData RegistryValueName RegistryValueType RemoteDeviceName RemoteIP RemoteIPType RemotePort RemoteUrl RemoteIp ReportId RequestAccountDomain RequestAccountName RequestAccountSid RequestProtocol RequestSourceIP RequestSourcePort SHA1 SHA256 SensitivityLabel SensitivitySubLabel Severity ShareName SignatureType Signer SignerHash Table Title TunnelType activityDateTime activityDisplayName additionalDetails{}.key additionalDetails{}.value categoryEvent correlationId initiatedBy.user.displayName initiatedBy.user.ipAddress initiatedBy.user.userPrincipalName loggedByService operationType result resultReason targetResources{}.displayName targetResources{}.id targetResources{}.modifiedProperties{}.displayName targetResources{}.modifiedProperties{}.newValue targetResources{}.modifiedProperties{}.oldValue targetResources{}.type targetResources{}.userPrincipalName resourceId resultSignature
```

## Using new field aliases

When using the TA-App [**Splunk Add-on for Microsoft Cloud Services**](https://splunkbase.splunk.com/app/3110/) for ingesting Azure Eventhub data (for example Azure AuditLogs, Azure SignInLogs, Defender for Endpoint Streaming API events)
JSON data will be correctly extracted using KV_MODE=json, but since data is nested JSON within body.records.properties the field naming will be ugly and inefficient:

## You want to have your fields readable again
<img src="/M365D_Splunk_TA_microsoft-cloudservices_fieldaliases.png" width="700" height="700" />

1. **Copy /apps/Splunk_TA_microsoft-cloudservices/default/props.conf to /apps/Splunk_TA_microsoft-cloudservices/local/props.conf**
2. **Edit local/props.conf and change stanza of**
   [mscs:azure:eventhub]
3. **Change to**:

```
[mscs:azure:eventhub]
TRUNCATE = 2097152
KV_MODE = json
TRANSFORMS-sourcetype_mscs_azure_security_alerts = mscs_azure_security_alerts
TRANSFORMS-sourcetype_mscs_azure_security_recommendations = mscs_azure_security_recommendations
############################################################################################################
# xknow: Begin of changes
# Set _time from _raw "body.records.time":{}                  (-> when event was ingested from eventhub)
# Set Timestamp from _raw "body.records.properties.Timestamp" (-> when event was detected via MDE)
# This addon will have equal functionality when it's finished (because Splunk wants MDE CIM support):
# https://github.com/splunk/TA-microsoft-365-defender-advanced-hunting-add-on/blob/master/default/props.conf    
TZ = UTC
TIME_PREFIX = \{"time": "
# xknow: Make Eventhub MDE streaming API fields directly readable (embedded nested json elements raw.body.records & raw.body.records.properties)
# Fieldalias does not support wildcard and we don't want to rename 30+ fields, sadly even the known REPORT-method does not work, so we have to go manually renaming each field...
# https://community.splunk.com/t5/Splunk-Search/Field-alias-or-batch-renaming-with-wildcard/td-p/351435
# https://community.splunk.com/t5/Getting-Data-In/Is-there-a-way-to-use-some-sort-of-regular-expression-with-field/m-p/300067
# https://community.splunk.com/t5/Getting-Data-In/How-can-we-extract-a-json-document-within-an-event/td-p/302227 
# make original times very clear
# TimeIngested = _time = body.records.time
FIELDALIAS-mscs_azure_eventhub_rawdata_timeingested = body.records.time as TimeIngested
# TimeDetected = body.records.properties.Timestamp
FIELDALIAS-mscs_azure_eventhub_rawdata_timedetected = body.records.properties.Timestamp as TimeDetected
# all other body.records aliases
FIELDALIAS-mscs_azure_eventhub_rawdata_tenantid = body.records.tenantId as tenantId
FIELDALIAS-mscs_azure_eventhub_rawdata_level = body.records.Level as Level
FIELDALIAS-mscs_azure_eventhub_rawdata_category = body.records.category as category
FIELDALIAS-mscs_azure_eventhub_rawdata_correlationid = body.records.correlationId as correlationId
FIELDALIAS-mscs_azure_eventhub_rawdata_durationms = body.records.durationMs as durationMs
FIELDALIAS-mscs_azure_eventhub_rawdata_operationname = body.records.operationName as operationName
FIELDALIAS-mscs_azure_eventhub_rawdata_operationversion = body.records.operationVersion as operationVersion
# all other body.record.properties aliases
FIELDALIAS-mscs_azure_eventhub_rawdata_aaddeviceid = body.records.properties.AadDeviceId as AadDeviceId
FIELDALIAS-mscs_azure_eventhub_rawdata_accountdomain = body.records.properties.AccountDomain as AccountDomain
FIELDALIAS-mscs_azure_eventhub_rawdata_accountname = body.records.properties.AccountName as AccountName
FIELDALIAS-mscs_azure_eventhub_rawdata_accountobjectid = body.records.properties.AccountObjectId as AccountObjectId
FIELDALIAS-mscs_azure_eventhub_rawdata_accountsid = body.records.properties.AccountSid as AccountSid
FIELDALIAS-mscs_azure_eventhub_rawdata_accountupn = body.records.properties.AccountUpn as AccountUpn
FIELDALIAS-mscs_azure_eventhub_rawdata_actiontype = body.records.properties.ActionType as ActionType
FIELDALIAS-mscs_azure_eventhub_rawdata_additionalfields = body.records.properties.AdditionalFields as AdditionalFields
FIELDALIAS-mscs_azure_eventhub_rawdata_alertid = body.records.properties.AlertId as AlertId
FIELDALIAS-mscs_azure_eventhub_rawdata_appguardcontainerid = body.records.properties.AppGuardContainerId as AppGuardContainerId
FIELDALIAS-mscs_azure_eventhub_rawdata_attacktechniques = body.records.properties.AttackTechniques as AttackTechniques
FIELDALIAS-mscs_azure_eventhub_rawdata_category_properties_big = body.records.properties.Category as Category
FIELDALIAS-mscs_azure_eventhub_rawdata_certificatecountersignaturetime = body.records.properties.CertificateCountersignatureTime as CertificateCountersignatureTime
FIELDALIAS-mscs_azure_eventhub_rawdata_certificatecreationtime = body.records.properties.CertificateCreationTime as CertificateCreationTime
FIELDALIAS-mscs_azure_eventhub_rawdata_certificateexpirationtime = body.records.properties.CertificateExpirationTime as CertificateExpirationTime
FIELDALIAS-mscs_azure_eventhub_rawdata_certificateserialnumber = body.records.properties.CertificateSerialNumber as CertificateSerialNumber
FIELDALIAS-mscs_azure_eventhub_rawdata_clientversion = body.records.properties.ClientVersion as ClientVersion
FIELDALIAS-mscs_azure_eventhub_rawdata_connectednetworks = body.records.properties.ConnectedNetworks as ConnectedNetworks
FIELDALIAS-mscs_azure_eventhub_rawdata_crldistributionpointurls = body.records.properties.CrlDistributionPointUrls as CrlDistributionPointUrls
FIELDALIAS-mscs_azure_eventhub_rawdata_defaultgateways = body.records.properties.DefaultGateways as DefaultGateways
FIELDALIAS-mscs_azure_eventhub_rawdata_deviceid = body.records.properties.DeviceId as DeviceId
FIELDALIAS-mscs_azure_eventhub_rawdata_devicename = body.records.properties.DeviceName as DeviceName
FIELDALIAS-mscs_azure_eventhub_rawdata_deviceobjectid = body.records.properties.DeviceObjectId as DeviceObjectId
FIELDALIAS-mscs_azure_eventhub_rawdata_dnsaddresses = body.records.properties.DnsAddresses as DnsAddresses
FIELDALIAS-mscs_azure_eventhub_rawdata_failurereason = body.records.properties.FailureReason as FailureReason
FIELDALIAS-mscs_azure_eventhub_rawdata_filename = body.records.properties.FileName as FileName
FIELDALIAS-mscs_azure_eventhub_rawdata_fileoriginIP = body.records.properties.FileOriginIP as FileOriginIP
FIELDALIAS-mscs_azure_eventhub_rawdata_fileoriginReferrerUrl = body.records.properties.FileOriginReferrerUrl as FileOriginReferrerUrl
FIELDALIAS-mscs_azure_eventhub_rawdata_fileoriginUrl = body.records.properties.FileOriginUrl as FileOriginUrl
FIELDALIAS-mscs_azure_eventhub_rawdata_filesize  = body.records.properties.FileSize as FileSize
FIELDALIAS-mscs_azure_eventhub_rawdata_folderpath = body.records.properties.FolderPath as FolderPath
FIELDALIAS-mscs_azure_eventhub_rawdata_ipaddresses = body.records.properties.IPAddresses as IPAddresses
FIELDALIAS-mscs_azure_eventhub_rawdata_ipv4dhcp = body.records.properties.IPv4Dhcp as IPv4Dhcp
FIELDALIAS-mscs_azure_eventhub_rawdata_ipv6dhcp = body.records.properties.IPv6Dhcp as IPv6Dhcp
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessaccountdomain = body.records.properties.InitiatingProcessAccountDomain as InitiatingProcessAccountDomain
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessaccountname = body.records.properties.InitiatingProcessAccountName as InitiatingProcessAccountName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessaccountobjectid = body.records.properties.InitiatingProcessAccountObjectId as InitiatingProcessAccountObjectId
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessaccountsid = body.records.properties.InitiatingProcessAccountSid as InitiatingProcessAccountSid
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessaccountupn = body.records.properties.InitiatingProcessAccountUpn as InitiatingProcessAccountUpn
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesscommandline = body.records.properties.InitiatingProcessCommandLine as InitiatingProcessCommandLine
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesscreationtime = body.records.properties.InitiatingProcessCreationTime as InitiatingProcessCreationTime
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessfilename = body.records.properties.InitiatingProcessFileName as InitiatingProcessFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessfilesize = body.records.properties.InitiatingProcessFileSize as InitiatingProcessFileSize
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessfolderpath = body.records.properties.InitiatingProcessFolderPath as InitiatingProcessFolderPath
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessid = body.records.properties.InitiatingProcessId as InitiatingProcessId
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessintegritylevel = body.records.properties.InitiatingProcessIntegrityLevel as InitiatingProcessIntegrityLevel
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesslogonid = body.records.properties.InitiatingProcessLogonId as InitiatingProcessLogonId
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessmd5 = body.records.properties.InitiatingProcessMD5 as InitiatingProcessMD5
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessparentcreationtime = body.records.properties.InitiatingProcessParentCreationTime as InitiatingProcessParentCreationTime
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessparentfilename = body.records.properties.InitiatingProcessParentFileName as InitiatingProcessParentFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessparentid = body.records.properties.InitiatingProcessParentId as InitiatingProcessParentId
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesssha1 = body.records.properties.InitiatingProcessSHA1 as InitiatingProcessSHA1
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesssha256 = body.records.properties.InitiatingProcessSHA256 as InitiatingProcessSHA256
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesssignaturestatus = body.records.properties.InitiatingProcessSignatureStatus as InitiatingProcessSignatureStatus
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesssignertype = body.records.properties.InitiatingProcessSignerType as InitiatingProcessSignerType
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocesstokenelevation = body.records.properties.InitiatingProcessTokenElevation as InitiatingProcessTokenElevation
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfocompanyname = body.records.properties.InitiatingProcessVersionInfoCompanyName as InitiatingProcessVersionInfoCompanyName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfofiledescription = body.records.properties.InitiatingProcessVersionInfoFileDescription as InitiatingProcessVersionInfoFileDescription
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfointernalfilename = body.records.properties.InitiatingProcessVersionInfoInternalFileName as InitiatingProcessVersionInfoInternalFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfooriginalfilename = body.records.properties.InitiatingProcessVersionInfoOriginalFileName as InitiatingProcessVersionInfoOriginalFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfoproductname = body.records.properties.InitiatingProcessVersionInfoProductName as InitiatingProcessVersionInfoProductName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatingprocessversioninfoproductversion = body.records.properties.InitiatingProcessVersionInfoProductVersion as InitiatingProcessVersionInfoProductVersion
FIELDALIAS-mscs_azure_eventhub_rawdata_isazureadjoined = body.records.properties.IsAzureADJoined as IsAzureADJoined
FIELDALIAS-mscs_azure_eventhub_rawdata_isazureinfoprotectionapplied = body.records.properties.IsAzureInfoProtectionApplied as IsAzureInfoProtectionApplied
FIELDALIAS-mscs_azure_eventhub_rawdata_islocaladmin = body.records.properties.IsLocalAdmin as IsLocalAdmin
FIELDALIAS-mscs_azure_eventhub_rawdata_isrootsignermicrosoft = body.records.properties.IsRootSignerMicrosoft as IsRootSignerMicrosoft
FIELDALIAS-mscs_azure_eventhub_rawdata_issigned = body.records.properties.IsSigned as IsSigned
FIELDALIAS-mscs_azure_eventhub_rawdata_istrusted = body.records.properties.IsTrusted as IsTrusted
FIELDALIAS-mscs_azure_eventhub_rawdata_issuer = body.records.properties.Issuer as Issuer
FIELDALIAS-mscs_azure_eventhub_rawdata_issuerhash = body.records.properties.IssuerHash as IssuerHash
FIELDALIAS-mscs_azure_eventhub_rawdata_localip = body.records.properties.LocalIP as LocalIP
FIELDALIAS-mscs_azure_eventhub_rawdata_localiptype = body.records.properties.LocalIPType as LocalIPType
FIELDALIAS-mscs_azure_eventhub_rawdata_localport = body.records.properties.LocalPort as LocalPort
FIELDALIAS-mscs_azure_eventhub_rawdata_loggedonusers = body.records.properties.LoggedOnUsers as LoggedOnUsers
FIELDALIAS-mscs_azure_eventhub_rawdata_logonid = body.records.properties.LogonId as LogonId
FIELDALIAS-mscs_azure_eventhub_rawdata_logontype = body.records.properties.LogonType as LogonType
FIELDALIAS-mscs_azure_eventhub_rawdata_md5 = body.records.properties.MD5 as MD5
FIELDALIAS-mscs_azure_eventhub_rawdata_macaddress = body.records.properties.MacAddress as MacAddress
FIELDALIAS-mscs_azure_eventhub_rawdata_machinegroup = body.records.properties.MachineGroup as MachineGroup
FIELDALIAS-mscs_azure_eventhub_rawdata_mitretechniques = body.records.properties.MitreTechniques as MitreTechniques
FIELDALIAS-mscs_azure_eventhub_rawdata_networkadaptername = body.records.properties.NetworkAdapterName as NetworkAdapterName
FIELDALIAS-mscs_azure_eventhub_rawdata_networkadapterstatus = body.records.properties.NetworkAdapterStatus as NetworkAdapterStatus
FIELDALIAS-mscs_azure_eventhub_rawdata_networkadaptertype = body.records.properties.NetworkAdapterType as NetworkAdapterType
FIELDALIAS-mscs_azure_eventhub_rawdata_osarchitecture = body.records.properties.OSArchitecture as OSArchitecture
FIELDALIAS-mscs_azure_eventhub_rawdata_osbuild = body.records.properties.OSBuild as OSBuild
FIELDALIAS-mscs_azure_eventhub_rawdata_osplatform = body.records.properties.OSPlatform as OSPlatform
FIELDALIAS-mscs_azure_eventhub_rawdata_osversion = body.records.properties.OSVersion as OSVersion
FIELDALIAS-mscs_azure_eventhub_rawdata_onboardingstatus = body.records.properties.OnboardingStatus as OnboardingStatus
FIELDALIAS-mscs_azure_eventhub_rawdata_previousfilename = body.records.properties.PreviousFileName as PreviousFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_previousfolderpath = body.records.properties.PreviousFolderPath as PreviousFolderPath
FIELDALIAS-mscs_azure_eventhub_rawdata_previousregistrykey = body.records.properties.PreviousRegistryKey as PreviousRegistryKey
FIELDALIAS-mscs_azure_eventhub_rawdata_previousregistryvaluedata = body.records.properties.PreviousRegistryValueData as PreviousRegistryValueData
FIELDALIAS-mscs_azure_eventhub_rawdata_previousregistryvaluename = body.records.properties.PreviousRegistryValueName as PreviousRegistryValueName
FIELDALIAS-mscs_azure_eventhub_rawdata_processcommandline = body.records.properties.ProcessCommandLine as ProcessCommandLine
FIELDALIAS-mscs_azure_eventhub_rawdata_processcreationtime = body.records.properties.ProcessCreationTime as ProcessCreationTime
FIELDALIAS-mscs_azure_eventhub_rawdata_processid = body.records.properties.ProcessId as ProcessId
FIELDALIAS-mscs_azure_eventhub_rawdata_processintegritylevel = body.records.properties.ProcessIntegrityLevel as ProcessIntegrityLevel
FIELDALIAS-mscs_azure_eventhub_rawdata_processtokenelevation = body.records.properties.ProcessTokenElevation as ProcessTokenElevation
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfocompanyname = body.records.properties.ProcessVersionInfoCompanyName as ProcessVersionInfoCompanyName
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfofiledescription = body.records.properties.ProcessVersionInfoFileDescription as ProcessVersionInfoFileDescription
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfointernalfilename = body.records.properties.ProcessVersionInfoInternalFileName as ProcessVersionInfoInternalFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfooriginalfilename = body.records.properties.ProcessVersionInfoOriginalFileName as ProcessVersionInfoOriginalFileName
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfoproductname = body.records.properties.ProcessVersionInfoProductName as ProcessVersionInfoProductName
FIELDALIAS-mscs_azure_eventhub_rawdata_processversioninfoproductversion = body.records.properties.ProcessVersionInfoProductVersion as ProcessVersionInfoProductVersion
FIELDALIAS-mscs_azure_eventhub_rawdata_protocol = body.records.properties.Protocol as Protocol
FIELDALIAS-mscs_azure_eventhub_rawdata_publicip = body.records.properties.PublicIP as PublicIP
FIELDALIAS-mscs_azure_eventhub_rawdata_registrydevicetag = body.records.properties.RegistryDeviceTag as RegistryDeviceTag
FIELDALIAS-mscs_azure_eventhub_rawdata_registrykey = body.records.properties.RegistryKey as RegistryKey
FIELDALIAS-mscs_azure_eventhub_rawdata_registryvaluedata = body.records.properties.RegistryValueData as RegistryValueData
FIELDALIAS-mscs_azure_eventhub_rawdata_registryvaluename = body.records.properties.RegistryValueName as RegistryValueName
FIELDALIAS-mscs_azure_eventhub_rawdata_registryvaluetype = body.records.properties.RegistryValueType as RegistryValueType
FIELDALIAS-mscs_azure_eventhub_rawdata_remotedevicename = body.records.properties.RemoteDeviceName as RemoteDeviceName
FIELDALIAS-mscs_azure_eventhub_rawdata_remoteip = body.records.properties.RemoteIP as RemoteIP
FIELDALIAS-mscs_azure_eventhub_rawdata_remoteiptype = body.records.properties.RemoteIPType as RemoteIPType
FIELDALIAS-mscs_azure_eventhub_rawdata_remoteport = body.records.properties.RemotePort as RemotePort
FIELDALIAS-mscs_azure_eventhub_rawdata_remoteurl = body.records.properties.RemoteUrl as RemoteUrl
FIELDALIAS-mscs_azure_eventhub_rawdata_remoteip = body.records.properties.RemoteIp as RemoteIp
FIELDALIAS-mscs_azure_eventhub_rawdata_reportid = body.records.properties.ReportId as ReportId
FIELDALIAS-mscs_azure_eventhub_rawdata_requestaccountdomain = body.records.properties.RequestAccountDomain as RequestAccountDomain
FIELDALIAS-mscs_azure_eventhub_rawdata_requestaccountname = body.records.properties.RequestAccountName as RequestAccountName
FIELDALIAS-mscs_azure_eventhub_rawdata_requestaccountsid = body.records.properties.RequestAccountSid as RequestAccountSid
FIELDALIAS-mscs_azure_eventhub_rawdata_requestprotocol = body.records.properties.RequestProtocol as RequestProtocol
FIELDALIAS-mscs_azure_eventhub_rawdata_requestsourceip = body.records.properties.RequestSourceIP as RequestSourceIP
FIELDALIAS-mscs_azure_eventhub_rawdata_requestsourceport = body.records.properties.RequestSourcePort as RequestSourcePort
FIELDALIAS-mscs_azure_eventhub_rawdata_sha1 = body.records.properties.SHA1 as SHA1
FIELDALIAS-mscs_azure_eventhub_rawdata_sha256 = body.records.properties.SHA256 as SHA256
FIELDALIAS-mscs_azure_eventhub_rawdata_sensitivitylabel = body.records.properties.SensitivityLabel as SensitivityLabel
FIELDALIAS-mscs_azure_eventhub_rawdata_sensitivitysublabel = body.records.properties.SensitivitySubLabel as SensitivitySubLabel
FIELDALIAS-mscs_azure_eventhub_rawdata_severity = body.records.properties.Severity as Severity
FIELDALIAS-mscs_azure_eventhub_rawdata_sharename = body.records.properties.ShareName as ShareName
FIELDALIAS-mscs_azure_eventhub_rawdata_signaturetype = body.records.properties.SignatureType as SignatureType
FIELDALIAS-mscs_azure_eventhub_rawdata_signer = body.records.properties.Signer as Signer
FIELDALIAS-mscs_azure_eventhub_rawdata_signerhash = body.records.properties.SignerHash as SignerHash
FIELDALIAS-mscs_azure_eventhub_rawdata_table = body.records.properties.Table as Table
FIELDALIAS-mscs_azure_eventhub_rawdata_title = body.records.properties.Title as Title
FIELDALIAS-mscs_azure_eventhub_rawdata_tunneltype = body.records.properties.TunnelType as TunnelType
FIELDALIAS-mscs_azure_eventhub_rawdata_activitydatetime = body.records.properties.activityDateTime as activityDateTime
FIELDALIAS-mscs_azure_eventhub_rawdata_activitydisplayname = body.records.properties.activityDisplayName as activityDisplayName
FIELDALIAS-mscs_azure_eventhub_rawdata_additionaldetails{}.key = body.records.properties.additionalDetails{}.key as additionalDetails{}.key
FIELDALIAS-mscs_azure_eventhub_rawdata_additionaldetails{}.value = body.records.properties.additionalDetails{}.value as additionalDetails{}.value
FIELDALIAS-mscs_azure_eventhub_rawdata_category_properties_small = body.records.properties.category as categoryEvent
FIELDALIAS-mscs_azure_eventhub_rawdata_correlationid = body.records.properties.correlationId as correlationId
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatedby.user.displayname = body.records.properties.initiatedBy.user.displayName as initiatedBy.user.displayName
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatedby.user.ipaddress = body.records.properties.initiatedBy.user.ipAddress as initiatedBy.user.ipAddress
FIELDALIAS-mscs_azure_eventhub_rawdata_initiatedby.user.userprincipalname = body.records.properties.initiatedBy.user.userPrincipalName as initiatedBy.user.userPrincipalName
FIELDALIAS-mscs_azure_eventhub_rawdata_loggedbyservice = body.records.properties.loggedByService as loggedByService
FIELDALIAS-mscs_azure_eventhub_rawdata_operationtype = body.records.properties.operationType as operationType
FIELDALIAS-mscs_azure_eventhub_rawdata_result = body.records.properties.result as result
FIELDALIAS-mscs_azure_eventhub_rawdata_resultreason = body.records.properties.resultReason as resultReason
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.displayname = body.records.properties.targetResources{}.displayName as targetResources{}.displayName
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.id = body.records.properties.targetResources{}.id as targetResources{}.id
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.modifiedproperties{}.displayname = body.records.properties.targetResources{}.modifiedProperties{}.displayName as targetResources{}.modifiedProperties{}.displayName
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.modifiedproperties{}.newvalue = body.records.properties.targetResources{}.modifiedProperties{}.newValue as targetResources{}.modifiedProperties{}.newValue
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.modifiedproperties{}.oldvalue = body.records.properties.targetResources{}.modifiedProperties{}.oldValue as targetResources{}.modifiedProperties{}.oldValue
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.type = body.records.properties.targetResources{}.type as targetResources{}.type
FIELDALIAS-mscs_azure_eventhub_rawdata_targetresources{}.userprincipalname = body.records.properties.targetResources{}.userPrincipalName as targetResources{}.userPrincipalName
FIELDALIAS-mscs_azure_eventhub_rawdata_resourceid = body.records.properties.resourceId as resourceId
FIELDALIAS-mscs_azure_eventhub_rawdata_resultsignature = body.records.properties.resultSignature as resultSignature
# xknow: End of changes
############################################################################################################
```

## Test all your new field aliases

If data exists for column, it should display now. Run the following Splunk SPL query to verify field aliases:

```
index=<your_search> sourcetype=mscs:azure:eventhub
| table _time TimeIngested TimeDetected tenantId Level category correlationId durationMs operationName operationVersion AadDeviceId AccountDomain AccountName AccountObjectId AccountSid AccountUpn ActionType AdditionalFields AlertId AppGuardContainerId AttackTechniques Category CertificateCountersignatureTime CertificateCreationTime CertificateExpirationTime CertificateSerialNumber ClientVersion ConnectedNetworks CrlDistributionPointUrls DefaultGateways DeviceId DeviceName DeviceObjectId DnsAddresses FailureReason FileName FileOriginIP FileOriginReferrerUrl FileOriginUrl as FolderPath IPAddresses IPv4Dhcp IPv6Dhcp InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessCreationTime InitiatingProcessFileName InitiatingProcessFileSize InitiatingProcessFolderPath InitiatingProcessId InitiatingProcessIntegrityLevel InitiatingProcessLogonId InitiatingProcessMD5 InitiatingProcessParentCreationTime InitiatingProcessParentFileName InitiatingProcessParentId InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessSignatureStatus InitiatingProcessSignerType InitiatingProcessTokenElevation InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion IsAzureADJoined IsAzureInfoProtectionApplied IsLocalAdmin IsRootSignerMicrosoft IsSigned IsTrusted Issuer IssuerHash LocalIP LocalIPType LocalPort LoggedOnUsers LogonId LogonType MD5 MacAddress MachineGroup MitreTechniques NetworkAdapterName NetworkAdapterStatus NetworkAdapterType OSArchitecture OSBuild OSPlatform OSVersion OnboardingStatus PreviousFileName PreviousFolderPath PreviousRegistryKey PreviousRegistryValueData PreviousRegistryValueName ProcessCommandLine ProcessCreationTime ProcessId ProcessIntegrityLevel ProcessTokenElevation ProcessVersionInfoCompanyName ProcessVersionInfoFileDescription ProcessVersionInfoInternalFileName ProcessVersionInfoOriginalFileName ProcessVersionInfoProductName ProcessVersionInfoProductVersion Protocol PublicIP RegistryDeviceTag RegistryKey RegistryValueData RegistryValueName RegistryValueType RemoteDeviceName RemoteIP RemoteIPType RemotePort RemoteUrl RemoteIp ReportId RequestAccountDomain RequestAccountName RequestAccountSid RequestProtocol RequestSourceIP RequestSourcePort SHA1 SHA256 SensitivityLabel SensitivitySubLabel Severity ShareName SignatureType Signer SignerHash Table Title TunnelType activityDateTime activityDisplayName additionalDetails{}.key additionalDetails{}.value categoryEvent correlationId initiatedBy.user.displayName initiatedBy.user.ipAddress initiatedBy.user.userPrincipalName loggedByService operationType result resultReason targetResources{}.displayName targetResources{}.id targetResources{}.modifiedProperties{}.displayName targetResources{}.modifiedProperties{}.newValue targetResources{}.modifiedProperties{}.oldValue targetResources{}.type targetResources{}.userPrincipalName resourceId resultSignature
```
