#dcerpc_data.py

# The `dcerpc_services` dictionary is a comprehensive map of several DCERPC services, their UUIDs, descriptions,
# versions, and associated methods along with operation numbers (opnums). This data structure can be utilized to
# identify and understand potential vulnerabilities or common attack patterns by APTs (Advanced Persistent Threats).
# Each service in the dictionary details specific RPC methods that may be targeted by APTs, with a focus on methods
# known to be exploited historically or which may pose potential security risks.

# Helpful reference: https://github.com/jsecurity101/MSRPC-to-ATTACK/tree/main

dcerpc_services = {
    "samr": {
        "UUID": "12345778-1234-ABCD-EF00-0123456789AC",
        "Action": "Security Account Manager (SAM) Remote Protocol (MS-SAMR) - samsrv.dll (loads into) lsass.exe",
        "Version": "1.0",
        "Methods": {
            6: {
                "Method": "SamrEnumerateDomainsInSamServer",
                "Note": "Potential APT abuse: mapping out the Active Directory domains within an organization to"
                        " understand its structure."
            },
            5: {
                "Method": "SamrLookupDomainInSamServer",
                "Note": "Potential APT abuse: resolving domain names to SIDs for lateral movement and privilege "
                        "escalation strategies."
            },
            17: {
                "Method": "SamrLookupNamesInDomain",
                "Note": "Potential APT abuse: translating usernames to RIDs could assist in account compromise efforts"
                        " by linking usernames to specific domain accounts."
            },
            13: {
                "Method": "SamrEnumerateUsersInDomain",
                "Note": "APT29 (Cozy Bear) has been known to enumerate user accounts to identify potential targets for"
                        " credential theft."
            },
            7: {
                "Method": "SamrOpenDomain",
                "Note": "Potential APT abuse: establishing a session with a domain object to perform reconnaissance or "
                        "carry out domain object modifications."
            },
            8: {
                "Method": "SamrQueryInformationDomain",
                "Note": "Potential APT abuse: extracting domain policies to tailor subsequent attacks, such as password"
                        " spraying, based on password policy knowledge."
            },
            18: {
                "Method": "SamrOpenUser",
                "Note": "Potential APT abuse: opening user objects to gather detailed information or to modify user "
                        "attributes for persistence or privilege escalation."
            },
            21: {
                "Method": "SamrQueryInformationUser",
                "Note": "Documented abuse includes querying last logon times to identify active users or group "
                        "memberships for targeted phishing campaigns."
            },
            27: {
                "Method": "SamrGetMembersInGroup",
                "Note": "Potential APT abuse: identifying group memberships, especially those with administrative "
                        "privileges, for targeted attacks."
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
                "Note": "APT groups might use this to enumerate privileged accounts for subsequent attacks."
            },
            44: {
                "Method": "LsarOpenPolicy2",
                "Note": "This method is typically used to gain access to policy objects which could be used to elevate "
                        "privileges or modify policy settings."
            },
            35: {
                "Method": "LsarEnumerateAccountsWithUserRight",
                "Note": "APT groups may use this to find accounts with specific rights, aiming to target accounts with "
                        "privileges ideal for further exploitation. The tactic aligns with the broader strategy of "
                        "privilege escalation."
            },
            3: {
                "Method": "LsarEnumerateTrustedDomains",
                "Note": "Enumerating trusted domains can help APT actors understand trust relationships for movement "
                        "between domains or to prepare for a Golden Ticket attack."
            },
            15: {
                "Method": "LsarLookupSids",
                "Note": "APT29 has been known to use SID-History injection, which could leverage methods like "
                        "LsarLookupSids to translate SIDs and ensure their injected SIDs correspond to high-privileged "
                        "accounts."
            },
            14: {
                "Method": "LsarLookupNames",
                "Note": "Mapping usernames to SIDs is a common step in privilege escalation. APT groups can use this "
                        "information to identify potential targets for token impersonation attacks."
            },
            30: {
                "Method": "LsarGetSystemAccessAccount",
                "Note": "By retrieving system access flags, APTs could determine the level of access of accounts, which"
                        " could be used to identify accounts with weak security settings."
            },
            36: {
                "Method": "LsarQueryInfoTrustedDomain",
                "Note": "APT actors might query trusted domain information to facilitate lateral movement across trust "
                        "boundaries within compromised Active Directory environments."
            },
            76: {
                "Method": "lsa_LookupSids3",
                "Note": "Threat actors may abuse lsa_LookupSids3 to resolve a list of SIDs to their corresponding "
                        "account names. This could be used during the reconnaissance phase to map out users, groups, "
                        "and relationships within an Active Directory environment. With this information, attackers "
                        "can identify high-privilege accounts for targeted attacks or further exploitation."
            },
            77: {
                "Method": "lsa_LookupNames4",
                "Note": "lsa_LookupNames4 could be abused by attackers to translate a batch of account names into "
                        "their corresponding SIDs. This can be a precursor to creating forged Kerberos tickets "
                        "(Golden Tickets), which allow attackers to assume the identity of virtually any account in "
                        "the Active Directory. It may also be used to identify accounts with certain privileges or "
                        "group memberships as potential targets for credential theft or privilege escalation."
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
                "Note": "APT groups like APT28 have used methods like this to enumerate network shares for lateral "
                        "movement and data harvesting."
            },
            16: {
                "Method": "NetrShareGetInfo",
                "Note": "APT29, also known as Cozy Bear, could potentially use this method to gather detailed "
                        "information about specific network shares."
            },
            20: {
                "Method": "NetSessionEnum",
                "Note": "APT groups may leverage this to gather information on active user sessions for targeted "
                        "attacks or to understand the scope of access on compromised accounts."
            },
            21: {
                "Method": "NetSessionDel",
                "Note": "APT1, known for strategic web compromises, could use this to discreetly remove sessions and "
                        "cover their tracks after data exfiltration."
            },
            28: {
                "Method": "NetFileEnum",
                "Note": "This method could be abused to surveil file usage patterns and identify critical assets, which "
                        "has been a tactic observed in the operations of APT10."
            },
            29: {
                "Method": "NetFileClose",
                "Note": "If abused, this method could be used to disrupt critical processes or to unlock files in use, "
                        "allowing for malicious modification or encryption by ransomware."
            },
            18: {
                "Method": "NetShareAdd",
                "Note": "APT groups might exploit this to discreetly create new network shares that facilitate the "
                        "exfiltration of stolen data or provide persistent network access."
            },
            19: {
                "Method": "NetShareDel",
                "Note": "Similar to the cleanup activities of APT32, this could be used post-exploitation to remove "
                        "evidence of unauthorized network shares."
            },
            22: {
                "Method": "NetShareSetInfo",
                "Note": "APT groups could potentially exploit this to modify share permissions, facilitating "
                        "unauthorized access to restricted data."
            }
        }
    },
    "drsuapi": {
        "UUID": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
        "Action": "DSRUAPI - DCSync, Rogue Domain Controller",
        "Version": "4.0",
        "Methods": {
            0: {
                "Method": "DsBind",
                "Note": "APT groups could potentially use DsBind to establish a persistent connection to a domain "
                        "controller."
            },
            1: {
                "Method": "DsUnbind",
                "Note": "Although DsUnbind itself is not directly exploitable for malicious purposes since it's used "
                        "to terminate a context handle with the directory service, threat actors might use it to "
                        "clean up after conducting operations that manipulate or extract data from a domain "
                        "controller. By unbinding properly, they could attempt to avoid leaving traces of their "
                        "activity that might be picked up by monitoring tools."
            },
            3: {
                "Method": "DRSGetNCChanges",
                "Note": "DRSGetNCChanges has been known to be used by various APT groups, such as APT29, in their "
                        "malware strain 'COZYDUKE'."
            },
            5: {
                "Method": "DsReplicaSync",
                "Note": "DsReplicaSync can be abused by APT groups to force synchronization of directory data."
            },
            7: {
                "Method": "DRSGetNT4ChangeLog",
                "Note": "DRSGetNT4ChangeLog has the potential for abuse in providing access to sensitive directory "
                        "changes."
            },
            8: {
                "Method": "DsReplicaAdd",
                "Note": "APT groups could theoretically use DsReplicaAdd to add a replication source reference."
            },
            9: {
                "Method": "DRSUpdateRefs",
                "Note": "DRSUpdateRefs has potential for abuse in managing the replication topology."
            },
            11: {
                "Method": "DsReplicaModify",
                "Note": "Manipulation of DsReplicaModify could potentially alter replication behavior to an attacker's "
                        "advantage."
            },
            12: {
                "Method": "DRSCrackNames",
                "Note": "DRSCrackNames can be exploited for reconnaissance, as seen in the activities of APT1."
            },
            13: {
                "Method": "DsWriteAccountSpn",
                "Note": "Used to write Service Principal Names (SPNs). A threat actor could abuse this method to "
                        "associate a SPN with an account they control or have compromised. This manipulation could "
                        "allow an attacker to carry out a Kerberoasting attack, which involves requesting Kerberos "
                        "tickets for services and then attempting to crack the tickets offline to reveal service "
                        "account passwords. Successfully exploiting this method could lead to the compromise of "
                        "service accounts which often have elevated privileges within a domain."
            },
            16: {
                "Method": "DsGetDomainControllerInfo",
                "Note": "DsGetDomainControllerInfo could be used by threat actors for gathering detailed information "
                        "about the domain controllers."
            },
            28: {
                "Method": "DRSAddEntry",
                "Note": "DRSAddEntry could potentially be exploited by APT groups to create objects in Active Directory."
            },
            34: {
                "Method": "DRSVerifyNames",
                "Note": "APT groups could potentially use DRSVerifyNames in an enumeration attack to verify the "
                        "existence of certain users or objects within AD."
            },
        }
    },
    "netlogon": {
        "UUID": "12345678-1234-abcd-ef00-01234567cffb",
        "Action": "NETLOGON - exploitation of remote services - zerologon",
        "Version": "1.0",
        "Methods": {
            4: {
                "Method": "NetrServerReqChallenge",
                "Note": "Used by attackers for establishing a secure channel with a domain controller."
            },
            21: {
                "Method": "NetrLogonDummyRoutine1",
                "Note": "While 'NetrLogonDummyRoutine1' is not a well-documented function and appears to be a "
                        "placeholder or unused function in the protocol specification, if it were implemented "
                        "incorrectly or if a threat actor found a way to leverage it, it could potentially be used "
                        "as a vector for attacks. A dummy routine, if it is callable and performs any action, might "
                        "be repurposed for malicious intent such as triggering buffer overflows or other unexpected "
                        "behaviors."
            },
            26: {
                "Method": "NetrServerAuthenticate3",
                "Note": "Targeted in the Zerologon vulnerability (CVE-2020-1472) for impersonation and privilege"
                        "escalation."
            },
            29: {
                "Method": "NetrLogonGetDomainInfo",
                "Note": "Threat actors could abuse 'NetrLogonGetDomainInfo' to gather detailed domain and network "
                        "information. This could include details about domain controllers, trust relationships, and "
                        "other configurations that could be leveraged for lateral movement or to plan further attacks. "
                        "It could also potentially be used to gather the session key if certain conditions are met, "
                        "which might allow for pass-the-hash and other credential-based attacks."
            },
            30: {
                "Method": "NetrServerPasswordSet2",
                "Note": "Abused in post-exploitation phases to change machine account passwords without knowing the "
                        "original password, effectively hijacking the machine's domain identity."
            },
            42: {
                "Method": "NetrServerGetTrustInfo",
                "Note": "Can be misused to obtain session keys and the trust account's password hash, which may be used "
                        "for forging inter-realm trust tickets (Silver Tickets)."
            },
            34: {
                "Method": "DsrGetDcNameEx2",
                "Note": "May be used by APTs for domain controller discovery in preparation for a DCSync attack, a "
                        "technique often used by APT29 (Cozy Bear)."
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
                "Note": "Opening the HKEY_LOCAL_MACHINE (HKLM) hive can provide an attacker with access to system-wide "
                        "settings and configurations."
            },
            5: {
                "Method": "OpenHKU",
                "Note": "Opening the HKEY_USERS (HKU) hive allows for modifications to the settings of the user profiles "
                        "on the system. The potential for abuse in establishing persistence or configuration tampering "
                        "exists."
            },
            22: {
                "Method": "RegSetValue",
                "Note": "RegSetValue can be used by malware to modify registry keys and values. This method was used by "
                        "the Stuxnet worm to propagate and change system configurations."
            },
            6: {
                "Method": "RegCreateKey",
                "Note": "APT groups may use RegCreateKey to create new registry keys for persistence or to store data for "
                        "later use."
            },
            8: {
                "Method": "RegDeleteKey",
                "Note": "RegDeleteKey could be used to remove evidence of an APT's presence or to disrupt system or "
                        "application functionality."
            },
            9: {
                "Method": "RegEnumKey",
                "Note": "RegEnumKey allows for the enumeration of subkeys, which could be used by APTs to gather "
                        "information or discover potential targets for further exploitation."
            },
            10: {
                "Method": "RegEnumValue",
                "Note": "RegEnumValue enables enumeration of registry values, which could be leveraged by APTs to scout "
                        "for configuration settings, potential vulnerabilities, or evidence of other malware."
            },
        }
    },
    "epm": {
        "UUID": "e1af8308-5d1f-11c9-91a4-08002b14a0fa",
        "Action": "Remote Procedure Call (RPC) Endpoint Mapper (EPM)",
        "Version": "3.0",
        "Methods": {
            2: {
                "Method": "ept_map",
                "Note": "The 'ept_map' function could be abused by an APT group to resolve RPC server interfaces and find"
                        " open ports and services for lateral movement or to identify potential targets. Recorded "
                        "incidents specifically using 'ept_map' are not commonly detailed, but the method is fundamental "
                        "in RPC-based reconnaissance."
            },
            3: {
                "Method": "ept_lookup",
                "Note": "APT groups might use 'ept_lookup' to enumerate available RPC services on a network. This method "
                        "was notably used in conjunction with the MS08-067 vulnerability by the Conficker worm to "
                        "propagate, which had APT-like features in terms of sophistication and impact, though Conficker "
                        "is not attributed to a state-sponsored APT."
            },
        }
    }
}
