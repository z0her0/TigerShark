#dcerpc_data.py

# The `dcerpc_services` dictionary is a comprehensive map of several DCERPC services, their UUIDs, descriptions,
# versions, and associated methods along with operation numbers (opnums). This data structure can be utilized to
# identify and understand potential vulnerabilities or common attack patterns by APTs (Advanced Persistent Threats).
# Each service in the dictionary details specific RPC methods that may be targeted by APTs, with a focus on methods
# known to be exploited historically or which may pose potential security risks.

# Helpful reference: https://github.com/jsecurity101/MSRPC-to-ATTACK/tree/main

dcerpc_services = {
    "drsuapi": {
        "UUID": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
        "Action": "MS-DRSR (Directory Replication Service) interface - DCSync, Rogue Domain Controller",
        "Version": "4.0",
        "Methods": {
            3: {
                "Method": "IDL_DRSGetNCChanges",
                "Note": "This function is exploited in DCSync attacks to mimic a Domain Controller and retrieve "
                        "directory information.",
                "ATT&CK TTP": "T1003.006 - DCSync",
                "Attack Type": "Credential Access via Directory Replication"
            },
            6: {
                "Method": "IDL_DRSReplicaModify",
                "Note": "Used to manipulate replication settings, potentially as part of a DCShadow attack to "
                        "maintain persistence or disrupt replication.",
                "ATT&CK TTP": "T1484.002 - Domain Policy Modification",
                "Attack Type": "Persistence, Privilege Escalation, or Disruption"
            },
            8: {
                "Method": "IDL_DRSReplicaAdd",
                "Note": "Can introduce a rogue Domain Controller to the replication process, allowing for "
                        "unauthorized AD alterations.",
                "ATT&CK TTP": "T1207 - Rogue Domain Controller",
                "Attack Type": "Persistence and Privilege Escalation"
            },
            9: {
                "Method": "IDL_DRSReplicaDel",
                "Note": "Removes replication sources, which could be used post-DCShadow attack to erase evidence "
                        "of unauthorized changes.",
                "ATT&CK TTP": "T1070.004 - File Deletion",
                "Attack Type": "Defense Evasion"
            },
            10: {
                "Method": "IDL_DRSUpdateRefs",
                "Note": "Updates replication references, which could be misused to add a rogue DC or disrupt "
                        "legitimate replication.",
                "ATT&CK TTP": "T1484 - Group Policy Modification",
                "Attack Type": "Persistence and Defense Evasion"
            },
            11: {
                "Method": "IDL_DRSReplicaModify",
                "Note": "Modifies replication settings, potentially to evade defenses or maintain unauthorized "
                        "access within an environment.",
                "ATT&CK TTP": "T1484.002 - Domain Policy Modification",
                "Attack Type": "Persistence and Defense Evasion"
            },
            12: {
                "Method": "IDL_DRSCrackNames",
                "Note": "Translates object names for replication changes, potentially used in reconnaissance to "
                        "map domain resources.",
                "ATT&CK TTP": "T1087.002 - Account Discovery: Domain Account",
                "Attack Type": "Discovery"
            },
            13: {
                "Method": "IDL_DRSWriteAccountSpn",
                "Note": "Writing SPNs could be abused in a Kerberoasting attack to gain access to service account "
                        "credentials.",
                "ATT&CK TTP": "T1558.003 - Kerberoasting",
                "Attack Type": "Credential Access"
            },
            15: {
                "Method": "IDL_DRSReplicaSync",
                "Note": "Requests immediate replication, which could be used in a DCSync attack to spread malicious "
                        "changes rapidly.",
                "ATT&CK TTP": "T1003.006 - DCSync",
                "Attack Type": "Credential Access and Lateral Movement"
            },
            16: {
                "Method": "IDL_DRSGetDomainControllerInfo",
                "Note": "Used to identify Domain Controllers, its unusual use might indicate reconnaissance by an "
                        "APT group.",
                "ATT&CK TTP": "T1018 - Remote System Discovery",
                "Attack Type": "Discovery"
            },
            28: {
                "Method": "IDL_DRSAddEntry",
                "Note": "This function can add or modify AD objects, potentially exploited by APTs to create "
                        "backdoors or escalate privileges.",
                "ATT&CK TTP": "T1136.002 - Create Account: Domain Account",
                "Attack Type": "Persistence, Privilege Escalation, and Initial Access"
            },
            34: {
                "Method": "IDL_DRSVerifyNames",
                "Note": "Can verify the existence of AD objects, which may be part of advanced reconnaissance "
                        "before targeted attacks.",
                "ATT&CK TTP": "T1087.002 - Account Discovery: Domain Account",
                "Attack Type": "Discovery"
            }
        }
    },
    "lsarpc": {
        "UUID": "12345778-1234-ABCD-EF00-0123456789ab",
        "Action": "LSARPC - Account discovery, domain group - Can be seen with enumeration activity",
        "Version": "3.0",
        "Methods": {
            9: {
                "Method": "LsarEnumerateAccounts",
                "Note": "This method can be used by APT groups to enumerate privileged accounts for subsequent "
                        "attacks.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery of Privileged Accounts"
            },
            44: {
                "Method": "LsarOpenPolicy2",
                "Note": "Accessing policy objects can be a step towards privilege elevation or policy settings "
                        "modifications.",
                "ATT&CK TTP": "T1484 - Domain Policy Modification",
                "Attack Type": "Privilege Escalation or Policy Manipulation"
            },
            35: {
                "Method": "LsarEnumerateAccountsWithUserRight",
                "Note": "Identifying accounts with specific user rights can help target accounts ideal for "
                        "exploitation.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
            },
            3: {
                "Method": "LsarEnumerateTrustedDomains",
                "Note": "Understanding trust relationships is crucial for movement between domains or for Golden "
                        "Ticket attacks.",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Lateral Movement Preparation"
            },
            15: {
                "Method": "LsarLookupSids",
                "Note": "Translating SIDs could be part of SID-History injection for assuming high-privileged "
                        "account identities.",
                "ATT&CK TTP": "T1178 - SID-History Injection",
                "Attack Type": "Privilege Escalation"
            },
            14: {
                "Method": "LsarLookupNames",
                "Note": "Mapping usernames to SIDs is useful for identifying potential targets for token "
                        "impersonation attacks.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Privilege Escalation and Reconnaissance"
            },
            30: {
                "Method": "LsarGetSystemAccessAccount",
                "Note": "System access flags can reveal the access level of accounts, highlighting those with "
                        "weak security.",
                "ATT&CK TTP": "T1003 - Credential Dumping",
                "Attack Type": "Discovery of Account Vulnerabilities"
            },
            36: {
                "Method": "LsarQueryInfoTrustedDomain",
                "Note": "Querying trusted domain info is vital for lateral movement across trust boundaries in "
                        "AD environments.",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Lateral Movement"
            },
            76: {
                "Method": "lsa_LookupSids3",
                "Note": "Resolving SIDs to account names can map out users and groups for further attacks within "
                        "AD environments.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Reconnaissance"
            },
            77: {
                "Method": "lsa_LookupNames4",
                "Note": "Translating account names to SIDs can aid in creating Golden Tickets and identifying "
                        "targets for escalation.",
                "ATT&CK TTP": "T1558.001 - Golden Ticket",
                "Attack Type": "Credential Theft and Privilege Escalation"
            }
        }
    },
    "netlogon": {
        "UUID": "12345678-1234-abcd-ef00-01234567cffb",
        "Action": "NETLOGON - exploitation of remote services - zerologon - netlogon.dll (loads into) lsass.exe",
        "Version": "1.0",
        "Methods": {
            2: {
                "Method": "NetrLogonSamLogon",
                "Note": "This function is involved in processing user logon requests and is susceptible to brute "
                        "force attacks if weak passwords are used.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
            },
            3: {
                "Method": "NetrLogonSamLogoff",
                "Note": "This method manages user logoff requests and can disrupt sessions, potentially being used "
                        "for denial-of-service attacks.",
                "ATT&CK TTP": "T1485 - Data Destruction",
                "Attack Type": "Denial of Service"
            },
            4: {
                "Method": "NetrServerReqChallenge",
                "Note": "Part of the secure channel establishment process, this method is used in the initial stages "
                        "of the Zerologon exploit.",
                "ATT&CK TTP": "T1075 - Pass the Hash",
                "Attack Type": "Credential Access via Zerologon"
            },
            6: {
                "Method": "NetrServerPasswordGet",
                "Note": "This method can be exploited to retrieve machine account passwords, aiding in lateral "
                        "movement or privilege escalation.",
                "ATT&CK TTP": "T1003 - Credential Dumping",
                "Attack Type": "Lateral Movement"
            },
            7: {
                "Method": "NetrDatabaseDeltas",
                "Note": "Used in domain replication, this method can be co-opted by attackers to intercept "
                        "sensitive replication data.",
                "ATT&CK TTP": "T1107 - File Deletion",
                "Attack Type": "Defense Evasion by Deleting Evidence"
            },
            21: {
                "Method": "NetrLogonDummyRoutine1",
                "Note": "While undocumented, if callable, this method could potentially be exploited for malicious "
                        "activities like buffer overflows.",
                "ATT&CK TTP": "T1190 - Exploit Public-Facing Application",
                "Attack Type": "Initial Access via Exploit"
            },
            26: {
                "Method": "NetrServerAuthenticate3",
                "Note": "Central to the Zerologon attack, this method can be used to bypass authentication controls "
                        "by changing the machine password.",
                "ATT&CK TTP": "T1557 - Man-in-the-Middle",
                "Attack Type": "Credential Access and Defense Evasion"
            },
            28: {
                "Method": "NetrServerTrustPasswordsGet",
                "Note": "This method can be abused to retrieve inter-domain trust passwords, potentially compromising"
                        " the entire AD forest.",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Discovery and Lateral Movement"
            },
            29: {
                "Method": "NetrLogonGetDomainInfo",
                "Note": "Can be used for extensive domain reconnaissance, potentially aiding in credential-based "
                        "attacks like pass-the-hash.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery and Credential Access"
            },
            30: {
                "Method": "NetrServerPasswordSet2",
                "Note": "This method is abused post-exploitation to alter machine account passwords, taking over "
                        "the machine's domain identity.",
                "ATT&CK TTP": "T1098 - Account Manipulation",
                "Attack Type": "Persistence and Privilege Escalation"
            },
            34: {
                "Method": "DsrGetDcNameEx2",
                "Note": "Often used for gathering information about domain controllers, this method can be a "
                        "precursor to a DCSync attack.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery for DCSync Attack"
            },
            42: {
                "Method": "NetrServerGetTrustInfo",
                "Note": "This method can be misused to forge inter-realm trust tickets, commonly known as Silver "
                        "Ticket attacks.",
                "ATT&CK TTP": "T1558.002 - Silver Ticket",
                "Attack Type": "Credential Access and Persistence"
            },
            44: {
                "Method": "NetrLogonSamLogonWithFlags",
                "Note": "This extended logon method may be vulnerable to similar attacks as NetrLogonSamLogon, "
                        "with added flag manipulation risks.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
            },
            45: {
                "Method": "NetrLogonSamLogonEx",
                "Note": "This enhanced logon function could be exploited for unauthorized access, potentially "
                        "enabling more sophisticated attacks.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
            }
        }
    },
    "samr": {
        "UUID": "12345778-1234-ABCD-EF00-0123456789AC",
        "Action": "Security Account Manager (SAM) Remote Protocol (MS-SAMR) - samsrv.dll (loads into) lsass.exe",
        "Version": "1.0",
        "Methods": {
            6: {
                "Method": "SamrEnumerateDomainsInSamServer",
                "Note": "Can be used by attackers to map out Active Directory domains within an organization, "
                        "understanding its structure for further attacks.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery"
            },
            5: {
                "Method": "SamrLookupDomainInSamServer",
                "Note": "May be used to resolve domain names to SIDs, aiding in lateral movement and privilege "
                        "escalation strategies by attackers.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
            },
            17: {
                "Method": "SamrLookupNamesInDomain",
                "Note": "Translating usernames to RIDs can help in account compromise by linking usernames to "
                        "specific domain accounts.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Credential Access"
            },
            13: {
                "Method": "SamrEnumerateUsersInDomain",
                "Note": "Used to enumerate user accounts, which can be exploited by threat actors to identify "
                        "targets for credential theft.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Credential Access"
            },
            7: {
                "Method": "SamrOpenDomain",
                "Note": "Allows establishing a session with a domain object, potentially for reconnaissance or "
                        "domain object modifications.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery"
            },
            8: {
                "Method": "SamrQueryInformationDomain",
                "Note": "Could be used to extract domain policies, informing attackers on how to tailor their "
                        "attacks, like password spraying.",
                "ATT&CK TTP": "T1201 - Password Policy Discovery",
                "Attack Type": "Credential Access"
            },
            18: {
                "Method": "SamrOpenUser",
                "Note": "Opening user objects can allow attackers to gather detailed information or modify "
                        "attributes for persistence or privilege escalation.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Persistence"
            },
            21: {
                "Method": "SamrQueryInformationUser",
                "Note": "Querying for user information such as last logon times can be used for targeting active "
                        "users in phishing or other campaigns.",
                "ATT&CK TTP": "T1078 - Valid Accounts",
                "Attack Type": "Credential Access"
            },
            27: {
                "Method": "SamrGetMembersInGroup",
                "Note": "Identifying group memberships, particularly administrative ones, can aid attackers in "
                        "targeting privileged accounts for attacks.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
            }
        }
    },
    "srvsvc": {
        "UUID": "4b324fc8-1670-01d3-1278-5a47bf6ee188",
        "Action": "SRVSVC - System Enumeration - srvsvc.dll (loads into) svchost.exe",
        "Version": "3.0",
        "Methods": {
            15: {
                "Method": "NetrShareEnum",
                "Note": "Can be used by APT groups to enumerate network shares for lateral movement and data "
                        "harvesting.",
                "ATT&CK TTP": "T1135 - Network Share Discovery",
                "Attack Type": "Discovery and Lateral Movement"
            },
            16: {
                "Method": "NetrShareGetInfo",
                "Note": "May be used by adversaries to gather detailed information about specific network shares.",
                "ATT&CK TTP": "T1082 - System Information Discovery",
                "Attack Type": "Discovery"
            },
            20: {
                "Method": "NetSessionEnum",
                "Note": "Could be leveraged by attackers to gather information on active user sessions for targeted "
                        "attacks or scope access.",
                "ATT&CK TTP": "T1049 - System Network Connections Discovery",
                "Attack Type": "Discovery"
            },
            21: {
                "Method": "NetSessionDel",
                "Note": "Might be used by threat actors to remove sessions and cover tracks after data exfiltration.",
                "ATT&CK TTP": "T1070 - Indicator Removal on Host",
                "Attack Type": "Defense Evasion"
            },
            28: {
                "Method": "NetFileEnum",
                "Note": "Can be abused to monitor file usage patterns and identify critical assets for attack planning.",
                "ATT&CK TTP": "T1083 - File and Directory Discovery",
                "Attack Type": "Discovery"
            },
            29: {
                "Method": "NetFileClose",
                "Note": "If abused, this could be used to interfere with critical processes or alter files, "
                        "potentially in ransomware attacks.",
                "ATT&CK TTP": "T1489 - Service Stop",
                "Attack Type": "Impact"
            },
            18: {
                "Method": "NetShareAdd",
                "Note": "Exploitable by APTs to create network shares for data exfiltration or persistent access.",
                "ATT&CK TTP": "T1135 - Network Share Discovery",
                "Attack Type": "Persistence and Lateral Movement"
            },
            19: {
                "Method": "NetShareDel",
                "Note": "Could be used post-compromise to remove evidence of unauthorized network shares.",
                "ATT&CK TTP": "T1070 - Indicator Removal on Host",
                "Attack Type": "Defense Evasion"
            },
            22: {
                "Method": "NetShareSetInfo",
                "Note": "May be exploited to change share permissions, allowing unauthorized data access.",
                "ATT&CK TTP": "T1222 - File and Directory Permissions Modification",
                "Attack Type": "Privilege Escalation"
            }
        }
    },
    "winreg": {
        "UUID": "338cd001-2244-31f1-aaaa-900038001003",
        "Action": "Remote Management and Monitoring (WinReg)",
        "Version": "1.0",
        "Methods": {
            2: {
                "Method": "OpenHKLM",
                "Note": "Provides access to system-wide settings and configurations through the HKLM hive.",
                "ATT&CK TTP": "T1112 - Modify Registry",
                "Attack Type": "Persistence, Privilege Escalation, and Configuration Tampering"
            },
            5: {
                "Method": "OpenHKU",
                "Note": "Allows for changes to user profiles via the HKU hive, potentially for persistence or "
                        "configuration tampering.",
                "ATT&CK TTP": "T1112 - Modify Registry",
                "Attack Type": "Persistence and Privilege Escalation"
            },
            22: {
                "Method": "RegSetValue",
                "Note": "Enables modification of registry keys and values, as seen in malware like Stuxnet for "
                        "propagation and system configuration changes.",
                "ATT&CK TTP": "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "Attack Type": "Persistence, Privilege Escalation, and System Compromise"
            },
            6: {
                "Method": "RegCreateKey",
                "Note": "Can be used to create new registry keys for storing data or establishing persistence.",
                "ATT&CK TTP": "T1136 - Create Account",
                "Attack Type": "Persistence via New Account Creation"
            },
            8: {
                "Method": "RegDeleteKey",
                "Note": "Potential for removing evidence of presence or disrupting system/application functionality.",
                "ATT&CK TTP": "T1485 - Data Destruction",
                "Attack Type": "Defense Evasion by Removing Evidence"
            },
            9: {
                "Method": "RegEnumKey",
                "Note": "Allows enumeration of subkeys, which can be used for reconnaissance of potential "
                        "exploitation targets.",
                "ATT&CK TTP": "T1082 - System Information Discovery",
                "Attack Type": "Discovery and Reconnaissance"
            },
            10: {
                "Method": "RegEnumValue",
                "Note": "Enables enumeration of registry values for scouting configuration settings or evidence "
                        "of other malware.",
                "ATT&CK TTP": "T1012 - Query Registry",
                "Attack Type": "Discovery and Information Gathering"
            }
        }
    }
}
