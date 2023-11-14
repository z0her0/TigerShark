"""  # pylint: disable=line-too-long
Module: dcerpc_data

This module defines structured data representations for DCERPC (Distributed Computing Environment/Remote Procedure Call)
services and their associated methods, focusing on identifying and understanding potential vulnerabilities and common
attack patterns leveraged by Advanced Persistent Threats (APTs). It includes detailed descriptions of several key DCERPC
services, their operation numbers (opnums), and specific RPC methods that are known targets for exploitation.

Classes:
- MethodDetails: Defines detailed information about specific methods in a DCERPC service, including potential attack
vectors and indicators of compromise.
- ServiceInfo: Encapsulates information about a DCERPC service, including its UUID, protocol, version, and methods.
- SummaryDetail: Provides summary information for various aspects of DCERPC services, offering a high-level overview
of their roles and characteristics.
- DcerpcData: A comprehensive collection of DCERPC data, including service details, summaries, and references.

Data:
- dcerpc_services: A dictionary containing a comprehensive map of DCERPC services, their methods, and associated
security implications. Each entry provides insights into how these services and methods might be exploited by APTs
and includes references to additional information.

The module is structured to facilitate easy access and interpretation of complex DCERPC data, serving as a valuable
resource for security analysis and threat modeling in network protocol environments.
"""

from typing import Dict, TypedDict

# pylint: disable=line-too-long

# The `dcerpc_services` dictionary is a comprehensive map of several DCERPC services, their UUIDs, descriptions,
# versions, and associated methods along with operation numbers (opnums). This data structure can be utilized to
# identify and understand potential vulnerabilities or common attack patterns by APTs (Advanced Persistent Threats).
# Each service in the dictionary details specific RPC methods that may be targeted by APTs, with a focus on methods
# known to be exploited historically or which may pose potential security risks.


class MethodDetails(TypedDict, total=False):
    """
    Represents detailed information about a specific method in a DCERPC service.

    Attributes:
        Method (str): The name of the method.
        Note (str): A note or description of the method.
        Attack_TTP (str): Tactics, Techniques, and Procedures used in attacks involving this method.
        Attack_Type (str): The type of attack associated with this method.
        IOC (str): Indicators of Compromise associated with this method.
    """
    Method: str
    Note: str
    Attack_TTP: str
    Attack_Type: str
    IOC: str


class ServiceInfo(TypedDict, total=False):
    """
    Represents information about a specific DCERPC service.

    Attributes:
        UUID (str): The Universal Unique Identifier of the service.
        Protocol (str): The protocol used by the service.
        Version (str): The version of the service.
        Methods (Dict[int, MethodDetails]): A dictionary mapping operation numbers (opnums) to their corresponding
        method details.
    """
    UUID: str
    Protocol: str
    Version: str
    Methods: Dict[int, MethodDetails]


class SummaryDetail(TypedDict):
    """
    Represents summary details for different aspects of DCERPC services.

    Attributes:
        overview (str): General overview of the DCERPC services.
        dcerpc (str): Details specific to the DCERPC protocol.
        ms_nrpc (str): Details specific to the MS-NRPC protocol.
        ms_drsr (str): Details specific to the MS-DRSR protocol.
        ms_lsad (str): Details specific to the MS-LSAD protocol.
        ms_srvs (str): Details specific to the MS-SRVS protocol.
        ms_samr (str): Details specific to the MS-SAMR protocol.
    """
    overview: str
    dcerpc: str
    ms_nrpc: str
    ms_drsr: str
    ms_lsad: str
    ms_srvs: str
    ms_samr: str


class DcerpcData(TypedDict, total=False):
    """
    Represents a comprehensive collection of DCERPC data, including service details and references.

    Attributes:
        summary (SummaryDetail): A summary of the DCERPC data.
        drsuapi (ServiceInfo): Information about the DRSUAPI service.
        lsarpc (ServiceInfo): Information about the LSARPC service.
        netlogon (ServiceInfo): Information about the NETLOGON service.
        samr (ServiceInfo): Information about the SAMR service.
        srvsvc (ServiceInfo): Information about the SRVSVC service.
        winreg (ServiceInfo): Information about the WINREG service.
        references (Dict[str, str]): A dictionary of references or sources of information.
    """
    summary: SummaryDetail
    drsuapi: ServiceInfo
    lsarpc: ServiceInfo
    netlogon: ServiceInfo
    samr: ServiceInfo
    srvsvc: ServiceInfo
    winreg: ServiceInfo
    references: Dict[str, str]


# pylint: disable=line-too-long
dcerpc_services = {
    "summary": {
        "overview": "Think of these protocols like different specialized tools in a toolbox, each with a specific \n"
                    "function in building and maintaining a house.\n\n",
        "dcerpc": "Distributed Computing Environment/Remote Procedure Call. This is the toolbox itself. It's a set \n"
                  "of rules that allows software programs to communicate over a network. Just like a toolbox that \n"
                  "holds various tools, DCERPC holds various protocols that help different parts of a network talk \n"
                  "to each other.\n\n",
        "ms_nrpc": "Netlogon Remote Protocol. This tool is like the security system of the house. It helps to \n"
                   "verify the identities of the 'residents' (users) and make sure that they are who they say \n"
                   "they are when they try to 'enter' (log in).\n\n",
        "ms_drsr": "Directory Replication Service. This is like the mail delivery system ensuring that all \n"
                   "residents get their mail. It replicates directory information, like user data and security \n"
                   "permissions, across different 'houses' (servers) to make sure everyone has up-to-date \n"
                   "information.\n\n",
        "ms_lsad": "Local Security Authority Remote Protocol. Consider this as the internal rules of the \n"
                   "house that manage who is allowed to do what. It deals with policies related to security \n"
                   "and permissions within a computer.\n\n",
        "ms_srvs": "Server Service Remote Protocol. This is like the maintenance crew who takes care of \n"
                   "sharing resources like printers or files over the network, similar to shared spaces in \n"
                   "a housing complex.\n\n",
        "ms_samr": "Security Account Manager Remote Protocol. This is like the human resources department \n"
                   "that manages employee records. It handles the details of security accounts, like users \n"
                   "and their passwords.\n\n"
    },
    "drsuapi": {
        "UUID": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
        "Protocol": "MS-DRSR (Directory Replication Service) interface - DCSync, Rogue Domain Controller",
        "Version": "4.0",
        "Methods": {
            0: {
                "Method": "IDL_DRSBind",
                "Note": "The IDL_DRSBind method creates a context handle that is necessary to call any other \n"
                        "method in this interface. This is like introducing yourself when you pick up the phone \n"
                        "and start a conversation.\n\n"
                        ""
                        "In a computer network, IDL_DRSBind is used to start a session between two systems that want \n"
                        "to communicate about replication. It's the way a computer says 'Hello, I'd like to talk \n"
                        "about keeping our user and computer information in sync,' to which the other system responds\n"
                        "by establishing a connection for them to communicate securely.",
                "Attack_TTP": "T1190: Exploit Public-Facing Application, T1210: Exploitation of Remote Services",
                "Attack_Type": "Initial System Compromise or Network Mapping",
                "IOC": "Irregular binding requests to the directory service, possibly indicating initial \n"
                       "exploitation or reconnaissance attempts."
            },
            1: {
                "Method": "IDL_DRSUnbind",
                "Note": "The IDL_DRSUnbind method destroys a context handle previously created by the IDL_DRSBind\n"
                        "method. This is the equivalent of saying 'Goodbye' at the end of a phone call. After two \n"
                        "systems have finished communicating about replication, IDL_DRSUnbind is used to end the \n"
                        "session. It's like one computer saying, 'Our conversation is finished, let's hang up the \n"
                        "line,' and the connection is closed properly.",
                "Attack_TTP": "T1485: Data Destruction, T1070: Indicator Removal on Host",
                "Attack_Type": "Post-Attack Cleanup or Evasion",
                "IOC": "Unusual or untimely unbinding operations on directory services, potentially indicative \n"
                       "of cleanup activities post-attack."
            },
            2: {
                "Method": "IDL_DRSReplicaSync",
                "Note": "Triggers replication from another DC, which could be used in a DCSync attack to spread \n"
                        "malicious changes rapidly. This is like a request to immediately send out any new updates or\n"
                        "changes. It's like calling a friend and saying, 'Hi, if you have any new news, tell me now!'\n"
                        "It's a way to ensure that a computer has the latest information without waiting for the \n"
                        "regular update schedule.",
                "Attack_TTP": "T1003.006 - DCSync",
                "Attack_Type": "Credential Access and Lateral Movement",
                "IOC": "Unusual synchronization patterns or rates, suggesting unauthorized data movement or \n"
                       "synchronization manipulation."
            },
            3: {
                "Method": "IDL_DRSGetNCChanges",
                "Note": "Replicates updates from an NC replica on the server. \n\n"
                        ""
                        "This function is exploited in DCSync attacks to mimic a DC and retrieve directory \n"
                        "information. \n\n"
                        ""
                        "So, IDL_DRSReplicaSync is about triggering an update across the network, and \n"
                        "IDL_DRSGetNCChanges is about getting the specifics of what has changed. They work together \n"
                        "to keep the entire network in sync and up-to-date.",
                "Attack_TTP": "T1003.006: OS Credential Dumping: DCSync, T1204: User Execution",
                "Attack_Type": "Credential Access via Directory Replication, Credential Harvesting or Reconnaissance",
                "IOC": "Anomalous replication requests, particularly those requesting large amounts of directory \n"
                       "data, indicative of credential harvesting or reconnaissance."
            },
            4: {
                "Method": "IDL_DRSUpdateRefs",
                "Note": "Updates replication references, which could be misused to add a rogue DC or disrupt \n"
                        "legitimate replication. \n\n"
                        ""
                        "Adds or deletes a value from the repsTo of a specified NC replica.\n\n"
                        ""
                        "This function is like updating the contact list on your phone. It manages references to \n"
                        "other computers that should receive updates. It's like telling your phone which friends to\n"
                        "keep in the loop about your news.",
                "Attack_TTP": "T1484.002 - Domain Trust Modification, T1583: Acquire Infrastructure: Domains, \n"
                              "T1584: Compromise Infrastructure",
                "Attack_Type": "Persistence and Defense Evasion, Infrastructure Hijacking or Traffic Redirection",
                "IOC": "Unexpected updates to replication references, which could signify an attempt to redirect\n"
                       "or manipulate replication traffic."
            },
            5: {
                "Method": "IDL_DRSReplicaAdd",
                "Note": "Adds a replication source reference for the specified NC. \n\n"
                        ""
                        "Can introduce a rogue Domain Controller to the replication process, allowing for \n"
                        "unauthorized AD alterations. This is like setting up a new delivery route in a postal \n"
                        "system. \n\n"
                        ""
                        "When you use this function, you're telling one server to start sharing information with \n"
                        "another server that it wasn't talking to before. It's like saying, 'Hey, start sending \n"
                        "copies of your files and updates over to this new server so it stays up-to-date with what's \n"
                        "happening.'",
                "Attack_TTP": "T1207 - Rogue Domain Controller, T1105: Ingress Tool Transfer, T1078: Valid Accounts",
                "Attack_Type": "Persistence and Privilege Escalation, Unauthorized Access or Persistence in Network",
                "IOC": "Unauthorized additions of directory replicas, potentially indicating lateral movement or \n"
                       "persistence attempts."
            },
            6: {
                "Method": "IDL_DRSReplicaDel",
                "Note": "Removes replication sources, which could be used post-DCShadow attack to erase evidence \n"
                        "of unauthorized changes.\n\n"
                        ""
                        "This function is the opposite of IDL_DRSReplicaAdd; it's like canceling a delivery route. \n"
                        "You're telling a server to stop sending its information to another server. It's like \n"
                        "telling the post office to stop delivering mail to an address because it's no longer in use \n"
                        "or needed.",
                "Attack_TTP": "T1070.004 - File Deletion, T1485: Data Destruction, T1486: Data Encrypted for Impact",
                "Attack_Type": "Defense Evasion, Directory Services Sabotage or Ransomware Preparation",
                "IOC": "Unexplained deletion or unbinding of directory replicas, indicative of sabotage or ransomware\n"
                       "preparation."
            },
            7: {
                "Method": "IDL_DRSReplicaModify",
                "Note": "Modifies replication settings, potentially to evade defenses or maintain unauthorized \n"
                        "access within an environment. Specifically, it's a function used in Windows Active \n"
                        "Directory environments that allows changes to be made to how domain controllers replicate\n"
                        "directory information among each other. \n\n"
                        ""
                        "This function is a part of the internal workings of Active Directory that helps \n"
                        "administrators or the system itself to manage the replication topology—the 'map' that \n"
                        "defines which controller talks to which and how often they exchange updates to ensure all of\n"
                        "them have the latest data.\n\n"
                        ""
                        "This one is more like setting up a schedule for when you call your friends and what topics \n"
                        "you'll talk about. It adjusts the details of how and when computers in the network sync up \n"
                        "their information.",
                "Attack_TTP": "T1484.002 - Domain Trust Modification, T1105, T1222",
                "Attack_Type": "Persistence and Defense Evasion, Replication Traffic Interception, Replication Data \n"
                               "Alteration",
                "IOC": "Modifications to replication settings, which might indicate attempts to intercept or \n"
                       "manipulate replication data."
            },
            8: {
                "Method": "IDL_DRSVerifyNames",
                "Note": "Resolves a sequence of object identities. \n\n"
                        ""
                        "Can verify the existence of AD objects, which may be part of advanced reconnaissance before \n"
                        "targeted attacks. \n\n"
                        ""
                        "This is like a verification service at a club who checks your ID to make sure you are who \n"
                        "you say you are before letting you in. In the context of a computer network, it checks the \n"
                        "names (like usernames or computer names) to confirm they exist and are correct within the \n"
                        "network's directory, which is like the club's guest list.",
                "Attack_TTP": "T1087.002 - Account Discovery: Domain Account, T1087, T1069",
                "Attack_Type": "Account Verification,Targeted Attack Preparation",
                "IOC": "Frequent verification requests for directory names, potentially for validating reconnaissance\n"
                       "data."
            },
            9: {
                "Method": "IDL_DRSGetMemberships",
                "Note": "Retrieves group membership for an object. Think of this as a club membership manager who \n"
                        "has a list of all the clubs each person belongs to. When someone wants to know what clubs a \n"
                        "user is a part of, this function provides that information. It tells you every group or \n"
                        "club within the network that the user is a member of.",
                "Attack_TTP": "T1069 - Permission Groups Discovery, T1069, T1087",
                "Attack_Type": "Privilege Discovery,User Group Mapping",
                "IOC": "Queries for group memberships, which could be a sign of privilege discovery."
            },
            10: {
                "Method": "IDL_DRSInterDomainMove",
                "Note": "Helper method used in a cross-NC move LDAP operation. \n\n"
                        ""
                        "This is like a moving service for user accounts. Imagine you have an account at a library \n"
                        "in one town and you move to another town. This service would transfer your account to your \n"
                        "new local library so you can borrow books there without creating a new account. In \n"
                        "technical terms, this function helps move an account from one domain to another within the \n"
                        "same forest (a collection of connected domains). It ensures that the account retains its \n"
                        "history and rights in the new domain.",
                "Attack_TTP": "T1105, T1098",
                "Attack_Type": "Lateral Movement, Unauthorized Domain Access",
                "IOC": "Movement of objects across domains, potentially indicating lateral movement or persistence \n"
                       "efforts."
            },
            11: {
                "Method": "IDL_DRSGetNT4ChangeLog",
                "Note": "If the server is the PDC emulator FSMO role owner, the IDL_DRSGetNT4ChangeLog \n"
                        "method returns either a sequence of PDC change log entries or the NT4 replication state, \n"
                        "or both, as requested by the client. \n\n"
                        ""
                        "This is like a history book or a log that keeps track of all the changes made in the \n"
                        "network related to user accounts and passwords, but specifically from old Windows NT 4.0 \n"
                        "systems. It's a way to look back at what has been done, which can be important for \n"
                        "understanding changes or for troubleshooting issues.",
                "Attack_TTP": "T1003, T1202",
                "Attack_Type": "Credential Dumping,Change Log Analysis",
                "IOC": "Accesses to the NT4 changelog, which could indicate attempts to extract credential or change \n"
                       "data."
            },
            12: {
                "Method": "IDL_DRSCrackNames",
                "Note": "Translates object names for replication changes, potentially used in reconnaissance to \n"
                        "map domain resources.\n\n"
                        ""
                        "IDL_DRSCrackNames helps ensure that when changes are made to objects in the directory \n"
                        "(like a user getting a new job title or a computer being moved to a new organizational unit),\n"
                        "these changes are correctly understood and distributed across the network, so all the domain \n"
                        "controllers have the same, updated information about these objects. It's a bit like a \n"
                        "translator that makes sure everyone is speaking the same language when they talk about who \n"
                        "or what is in the network and any updates to it.",
                "Attack_TTP": "T1087.002 - Account Discovery: Domain Account, T1087, T1069",
                "Attack_Type": "Account Enumeration,Directory Reconnaissance",
                "IOC": "High volume of name resolution requests, potentially for account enumeration."
            },
            13: {
                "Method": "IDL_DRSWriteAccountSpn",
                "Note": "Updates the set of SPNs on an object. "
                        ""
                        "Writing SPNs could be abused in a Kerberoasting attack to gain access to service account \n"
                        "credentials. \n\n"
                        ""
                        "This function is like a labeling machine for user accounts. SPN stands for Service Principal\n"
                        "Name, which is essentially a unique identifier for a service on a network. By modifying \n"
                        "SPNs, this function can change the labels attached to user accounts, which can affect how \n"
                        "users or services prove their identity on the network. If someone changes these labels \n"
                        "incorrectly or maliciously, it could allow unauthorized access to network services.",
                "Attack_TTP": "T1134, T1078",
                "Attack_Type": "Credential Access via SPN Manipulation,Unauthorized Directory Modifications",
                "IOC": "Modifications to Service Principal Names (SPNs) that are abnormal or unauthorized."
            },
            14: {
                "Method": "IDL_DRSRemoveDsServer",
                "Note": "Removes the representation (also known as metadata) of a DC from the directory. \n\n"
                        ""
                        "Imagine you have a bunch of managers (servers) in a big company (the network), and each \n"
                        "manager has a specific role. Now, if the company decides that one of the managers is no \n"
                        "longer needed, it uses a process (this function) to officially remove that manager from \n"
                        "their role. In network terms, this function is used to remove a domain controller (a server \n"
                        "that manages network security and user information) from the network.",
                "Attack_TTP": "T1485, T1486",
                "Attack_Type": "Server Object Tampering,Directory Service Disruption",
                "IOC": "Unusual deletion or removal of server objects from the directory service."
            },
            15: {
                "Method": "IDL_DRSRemoveDsDomain",
                "Note": "Removes the representation (also known as metadata) of a domain from the directory. \n\n"
                        ""
                        "Think of a company with different departments (domains). If the company decides to \n"
                        "completely shut down a whole department, it would use a specific process (this function) \n"
                        "to do so. In the context of a network, this function is used to remove an entire domain, \n"
                        "which is a subdivision within an Active Directory environment. This could mean taking down \n"
                        "all the management and infrastructure related to a particular subset of the network.",
                "Attack_TTP": "T1485, T1486",
                "Attack_Type": "Domain Sabotage,Directory Services Manipulation",
                "IOC": "Removal of domain-related objects, possibly indicating sabotage or domain manipulation."
            },
            16: {
                "Method": "IDL_DRSDomainControllerInfo",
                "Note": "Retrieves information about DCs in a given domain. \n\n"
                        ""
                        "Used to identify Domain Controllers, its unusual use might indicate reconnaissance by an \n"
                        "APT group. \n\n"
                        ""
                        "This function is like asking the HR department for a list of all the managers (domain \n"
                        "controllers) and their departments (domains) across the company, including details about \n"
                        "their roles and responsibilities. It's a way to get an overview of who's who and which \n"
                        "department they're overseeing. The 'opnum' here is like a different form number for this \n"
                        "type of request.",
                "Attack_TTP": "T1018 - Remote System Discovery, T1016, T1087",
                "Attack_Type": "Discovery, Reconnaissance and Intelligence Gathering,Domain Controller Mapping",
                "IOC": "Excessive queries for domain controller information, indicating reconnaissance."
            },
            17: {
                "Method": "IDL_DRSAddEntry",
                "Note": "This function can add or modify AD objects, potentially exploited by APTs to create \n"
                        "backdoors or escalate privileges. \n\n"
                        ""
                        "Think of this function as a way to add new entries into a phone book. It's used to create \n"
                        "new objects, like user or computer accounts, in the Active Directory database. If used \n"
                        "improperly, it could allow someone to insert false or unauthorized entries into the \n"
                        "network's 'phone book,' which could be used for malicious purposes like creating fake user \n"
                        "accounts.",
                "Attack_TTP": "T1136.002 - Create Account: Domain Account, T1069, T1087",
                "Attack_Type": "Persistence, Privilege Escalation, and Initial Access, Unauthorized Directory Object\n"
                               " Modification, Privilege Escalation Attempt",
                "IOC": "Unusual addition of new directory objects or entries, particularly those with elevated \n"
                       "privileges."
            },
            18: {
                "Method": "IDL_DRSExecuteKCC",
                "Note": "Validates the replication interconnections of DCs and updates them if necessary. \n\n"
                        ""
                        "This function is like calling a network technician to optimize your office's internet \n"
                        "network. It triggers a process that checks and organizes the best paths for communication \n"
                        "between servers that manage logins and data security in a company's computer network. It's \n"
                        "like ensuring that all the cables and Wi-Fi signals are arranged for the best speed and \n"
                        "efficiency, so information flows smoothly and reliably.",
                "Attack_TTP": "T1489, T1222",
                "Attack_Type": "Network Topology Manipulation,Unauthorized Domain Control Actions",
                "IOC": "Unexpected execution of the Knowledge Consistency Checker (KCC), potentially indicating \n"
                       "manipulation of domain topology."
            },
            19: {
                "Method": "IDL_DRSGetReplInfo",
                "Note": "Retrieves the replication state of the server. \n\n"
                        ""
                        "This function is akin to asking for a detailed report on how the mail has been moving \n"
                        "around in your office. It provides information about how data is being shared and \n"
                        "synchronized between the servers in charge of keeping user information and security \n"
                        "settings up-to-date. If you're managing the network, this report would tell you if \n"
                        "everything is being shared correctly or if there are any delays or problems.",
                "Attack_TTP": "T1203, T1087",
                "Attack_Type": "Directory Replication Surveillance,Replication Data Mining",
                "IOC": "Excessive or unusual requests for replication information from the directory."
            },
            20: {
                "Method": "IDL_DRSAddSidHistory",
                "Note": "Adds one or more SIDs to the sIDHistory attribute of a given object. \n\n"
                        ""
                        "Imagine you've got a user who's moving from one department to another and you want to make \n"
                        "sure they can still access their old files as well as the new ones. IDL_DRSAddSidHistory is \n"
                        "like updating their keycard so it works on doors in both departments. It adds a user's old \n"
                        "identification from a previous domain to their new account in another domain, so they \n"
                        "can access resources from both without issue.",
                "Attack_TTP": "T1134, T1484",
                "Attack_Type": "SID History Injection,Access Token Manipulation",
                "IOC": "Unauthorized attempts to add or modify SID history in directory objects."
            },
            21: {
                "Method": "IDL_DRSGetMemberships2",
                "Note": "Retrieves group memberships for a sequence of objects. \n\n"
                        ""
                        "Think about when someone needs to know what clubs or groups a person belongs to within \n"
                        "a company. IDL_DRSGetMemberships2 is like looking up all the teams and committees a person \n"
                        "is a part of. This function checks which groups a user is a member of, which can help in \n"
                        "giving them the correct access to files and systems they need for those groups.",
                "Attack_TTP": "T1069 - Permission Groups Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Unusual patterns or a high volume of queries to retrieve group memberships of users, \n"
                       "particularly if focused on accounts with elevated permissions or in sensitive groups, \n"
                       "which might indicate an attempt to discover permission groups for subsequent exploitation \n"
                       "or access escalation."
            },
            22: {
                "Method": "IDL_DRSReplicaVerifyObjects",
                "Note": "Verifies the existence of objects in an NC replica by comparing against a replica \n"
                        "of the same NC on a reference DC, optionally deleting any objects that do not exist \n"
                        "on the reference DC. \n\n"
                        ""
                        "Think of Active Directory as a city's information center where all the details about its \n"
                        "citizens and their roles are stored. Imagine this function as a quality checker in the \n"
                        "information center. It's like having someone go through the records to make sure no false \n"
                        "information has been added. If the city had a fake citizen added to its records, this tool \n"
                        "would help find and remove that false entry. This ensures that only valid and accurate \n"
                        "information is shared across the network. The 'opnum' for this function is the unique \n"
                        "identifier that tells the system to perform this specific check.",
                "Attack_TTP": "T1003.006, T1203",
                "Attack_Type": "Replication Integrity Tampering,Unauthorized Data Access",
                "IOC": "Unusual replication verification requests that could suggest attempts to access or \n"
                       "manipulate directory data."
            },
            23: {
                "Method": "IDL_DRSGetObjectExistence",
                "Note": "Helps the client check the consistency of object existence between its replica of an NC \n"
                        "and the server's replica of the same NC. Checking the consistency of object existence \n"
                        "means identifying objects that have replicated to both replicas and that exist in one \n"
                        "replica but not in the other. For the purposes of this method, an object exists within a \n"
                        "NC replica if it is either an object or a tombstone.\n\n"
                        ""
                        "Think of Active Directory as a city's information center where all the details about \n"
                        "its citizens and their roles are stored. This function is like a roll call tool. It helps \n"
                        "the information center check if they have all the expected records. If some citizens were \n"
                        "supposed to send in their details and the center isn't sure if they've received them all, \n"
                        "this tool would help confirm whether anything is missing or if there are any extra, \n"
                        "unexpected records.",
                "Attack_TTP": "T1087, T1016",
                "Attack_Type": "Mapping Directory Services, Reconnaissance Activity",
                "IOC": "Excessive queries for object existence, potentially indicating reconnaissance or mapping \n"
                       "of directory services."
            },
            25: {
                "Method": "IDL_DRSInitDemotion",
                "Note": "Performs the first phase of the removal of a DC from an AD LDS forest. This method is \n"
                        "supported only by AD LDS. \n\n"
                        ""
                        "This is like starting a retirement process for a manager. It prepares the domain controller \n"
                        "to be demoted by making sure all the initial conditions are met and everything is in place \n"
                        "for a smooth transition.",
                "Attack_TTP": "T1489, T1108",
                "Attack_Type": "Unauthorized Demotion Processes, Domain Controller Destabilization",
                "IOC": "Initial demotion activities on domain controllers that do not align with standard \n"
                       "operational procedures."
            },
            26: {
                "Method": "IDL_DRSReplicaDemotion",
                "Note": "Replicates off all changes to the specified NC and moves any FSMOs held to another server.\n\n"
                        ""
                        "This function is like handing over the responsibilities and data that the manager had to \n"
                        "other managers. It ensures that all the important information this domain controller has \n"
                        "is replicated or transferred to other domain controllers before it is demoted.",
                "Attack_TTP": "T1489, T1108",
                "Attack_Type": "Replication Manipulation, Domain Controller Compromise",
                "IOC": "Unexpected replication changes or demotion requests for domain controllers."
            },
            27: {
                "Method": "IDL_DRSFinishDemotion",
                "Note": "Either performs one or more steps toward the complete removal of a DC from an AD LDS forest,\n"
                        "or it undoes the effects of the first phase of removal (performed by IDL_DRSInitDemotion).\n"
                        "This method is supported by AD LDS only. This is the final step in the retirement process. \n"
                        "After all the data and duties have been handed off, this function completes the demotion, \n"
                        "essentially removing the manager's status and ensuring the office can run smoothly without \n"
                        "them.",
                "Attack_TTP": "T1489, T1108",
                "Attack_Type": "Domain Controller Demotion,Network Destabilization",
                "IOC": "Unusual demotion activities in domain controllers, especially if unauthorized."
            },
            28: {
                "Method": "IDL_DRSAddCloneDC",
                "Note": "Used to create a new DC object by copying attributes from an existing DC object. \n\n"
                        ""
                        "This function is like a cloning tool. Imagine you have a security guard (a domain controller)\n"
                        "that has a set of keys (security information) to many different doors in a building \n"
                        "(the network). If you want to create an exact copy of that guard with the same keys, so \n"
                        "he can help with the workload or replace the original guard if he's unavailable, you would \n"
                        "use this tool. It's used to make an exact replica of a domain controller, which can be \n"
                        "helpful for balancing the load of network traffic or for setting up a new controller \n"
                        "without having to configure everything from scratch.",
                "Attack_TTP": "T1078, T1108",
                "Attack_Type": "Unauthorized Domain Controller Cloning, Impersonation Attack",
                "IOC": "Creation of unexpected or unauthorized domain controller clones."
            },
            29: {
                "Method": "IDL_DRSWriteNgcKey",
                "Note": "Composes and updates the msDS-KeyCredentialLink value on an object. \n\n"
                        ""
                        "This function is like a key maker. It allows you to create or replace a specific type of \n"
                        "key (known as a Next Generation Credentials key, which is used for modern authentication \n"
                        "methods) for a user's account. This could be used if you need to update or reset the way \n"
                        "a user logs into the network to ensure their credentials are up-to-date and secure.",
                "Attack_TTP": "T1003, T1558",
                "Attack_Type": "Unauthorized Credential Modification, Key Manipulation",
                "IOC": "Unauthorized write operations or modifications to NGC keys."
            },
            30: {
                "Method": "IDL_DRSReadNgcKey",
                "Note": "Reads and parses the msDS-KeyCredentialLink value on an object. \n\n"
                        ""
                        "This function is like a specific request to the HR department for the key code to the \n"
                        "company's secure Wi-Fi network that only certain smartphones (specifically those belonging \n"
                        "to executives) can access. The 'opnum' is like a specific form number that you'd have to \n"
                        "fill out to get this information. In technical terms, this function reads the data related \n"
                        "to Next Generation Credentials (NGC), which are a type of more secure digital keys used for\n"
                        "authentication.",
                "Attack_TTP": "T1003, T1558",
                "Attack_Type": "Credential Access, Key Compromise",
                "IOC": "Unusual access or read requests for NGC keys from non-standard accounts."
            },
        }
    },
    "lsarpc": {
        "UUID": "12345778-1234-ABCD-EF00-0123456789ab",
        "Protocol": "LSARPC (Local Security Authority (LSA) Remote Procedure Call) interface - Account discovery, "
                    "domain group - Can be seen with enumeration activity",
        "Version": "3.0",
        "Methods": {
            11: {
                "Method": "LsarEnumerateAccounts",
                "Note": "This method can be used by APT groups to enumerate privileged accounts for subsequent \n"
                        "attacks. \n\n"
                        ""
                        "This method is invoked to request a list of account objects in the server's database. The \n"
                        "method can be called multiple times to return its output in fragments. \n\n"
                        ""
                        "This function is like asking the security office of a company to give you a list of all the \n"
                        "employee badges. It's a way to get an overview of all the user accounts that the security \n"
                        "system is keeping track of. You might do this to see who has access to the building, for \n"
                        "example.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Discovery of Privileged Accounts",
                "IOC": "Increased queries to enumerate account objects, especially those with elevated privileges \n"
                       "or in critical organizational units."
            },
            13: {
                "Method": "LsarEnumerateTrustedDomains",
                "Note": "Understanding trust relationships is crucial for movement between domains or for Golden \n"
                        "Ticket attacks. \n\n"
                        ""
                        "Tis invoked to request a list of trusted domain objects in the server's database. The method\n"
                        "can be called multiple times to return its output in fragments. This function used to get a \n"
                        "list of all the trusted domains that a server knows about.\n\n"
                        ""
                        "A domain is like a neighborhood, and a trusted domain is a neighborhood that's considered \n"
                        "friendly and safe. So, if you wanted to know which neighborhoods your local community \n"
                        "center trusts for its members to visit, this function would provide you with that information",
                "Attack_TTP": "T1482 - Domain Trust Discovery",
                "Attack_Type": "Lateral Movement Preparation",
                "IOC": "Unusual requests or spikes in queries for trusted domain objects, indicating reconnaissance \n"
                       "of trust relationships."
            },
            14: {
                "Method": "LsarLookupNames",
                "Note": "The LsarLookupNames method translates a batch of security principal names to their SID \n"
                        "form. It also returns the domains that these names are a part of. Mapping usernames to SIDs \n"
                        "is useful for identifying potential targets for token impersonation attacks. This does the \n"
                        "opposite of LsarLookupSids. It takes a list of user account or group names and finds out \n"
                        "their corresponding SIDs. \n\n"
                        ""
                        "It's like asking a receptionist to find the office and job title for a person just by their \n"
                        "name. This function takes a list of user names and figures out their respective job titles \n"
                        "(in technical terms, their security identifiers or SIDs).",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Privilege Escalation and Reconnaissance",
                "IOC": "High volume of name-to-SID resolution requests, particularly for high-privilege or \n"
                       "administrative accounts."
            },
            15: {
                "Method": "LsarLookupSids",
                "Note": "The LsarLookupSids method translates a batch of security principal SIDs to their name \n"
                        "forms. It also returns the domains that these names are a part of. Translating SIDs \n"
                        "could be part of SID-History injection for assuming high-privileged account identities. \n\n"
                        ""
                        "This function takes a list of SIDs (Security Identifiers), which are unique codes that \n"
                        "identify user accounts or groups within a computer network, and finds out the names of \n"
                        "those user accounts or groups. It's like looking up a list of customer numbers to find \n"
                        "the actual names of the customers.",
                "Attack_TTP": "T1178 - SID-History Injection",
                "Attack_Type": "Privilege Escalation",
                "IOC": "Multiple SID-to-name translation requests that could indicate attempts at mapping network \n"
                       "privileges or account reconnaissance."
            },
            23: {
                "Method": "LsarGetSystemAccessAccount",
                "Note": "The LsarGetSystemAccessAccount method is invoked to retrieve system access account flags \n"
                        "for an account object. System access flags can reveal the access level of accounts, \n"
                        "highlighting those with weak security. \n\n"
                        ""
                        "This function is used to retrieve specific settings (referred to as 'system access account \n"
                        "flags') that determine what a user account is permitted to do on the network. It's like \n"
                        "checking what services a customer has signed up for based on their account information.",
                "Attack_TTP": "T1003 - Credential Dumping",
                "Attack_Type": "Discovery of Account Vulnerabilities",
                "IOC": "Queries for system access account flags that are not part of routine checks, possibly \n"
                       "indicating a search for accounts with weak security."
            },
            26: {
                "Method": "LsarQueryInfoTrustedDomain",
                "Note": "Querying trusted domain info is vital for lateral movement across trust boundaries in \n"
                        "AD environments. \n\n"
                        ""
                        "This function is invoked to retrieve information about the trusted domain object. \n\n"
                        ""
                        "This function is like going into the records of a 'trusted' department in a company and \n"
                        "pulling out specific files to learn more about it. It could be details about their policies,\n"
                        "the way they operate, or the agreements they have with your own department.\n",
                "Attack_TTP": "T1482 - Domain Trust Discovery",
                "Attack_Type": "Lateral Movement",
                "IOC": "Elevated frequency of requests for information about trusted domains, potentially for \n"
                       "planning cross-domain lateral movements."
            },
            35: {
                "Method": "LsarEnumerateAccountsWithUserRight",
                "Note": "Identifying accounts with specific user rights can help target accounts ideal for \n"
                        "exploitation. \n\n"
                        ""
                        "Invoked to return a list of account objects that have the user right equal \n"
                        "to the passed-in value. This method lets you list all the accounts that have a \n"
                        "specific right or permission in the system. For example, if you want to see a list \n"
                        "of all the people in a company who have the key to the storage room, this function \n"
                        "would give you that list.",
                "Attack_TTP": "T1069 - Permission Groups Discovery",
                "Attack_Type": "Privilege Escalation",
                "IOC": "Frequent requests to enumerate accounts with specific user rights, possibly to identify \n"
                       "accounts with exploitable privileges."
            },
            44: {
                "Method": "LsarOpenPolicy2",
                "Note": "Accessing policy objects can be a step towards privilege elevation or policy settings \n"
                        "modifications. This method opens a context handle to the RPC server. This is the first \n"
                        "function that MUST be called to contact the Local Security Authority (Domain Policy) \n"
                        "Remote Protocol database. \n\n"
                        ""
                        "This is like asking for permission to look at or change the company's security policies. \n"
                        "Before you can make any changes or even just view the policies, you need to get the keys to \n"
                        "the policy file cabinet. This function gets you those keys if you're authorized.",
                "Attack_TTP": "T1484 - Domain Policy Modification, T1087: Account Discovery",
                "Attack_Type": "Privilege Escalation or Policy Manipulation",
                "IOC": "Unusual or unauthorized attempts to access or modify LSA policy settings, indicating \n"
                       "potential policy manipulation or privilege escalation attempts."
            },
            45: {
                "Method": "LsarGetUserName",
                "Note": "Returns the name and the domain name of the security principal that is invoking the method. \n"
                        "This is like asking, 'Who am I?' to the receptionist. It’s a simple request that tells you \n"
                        "your own name and job title as per the office records.",
                "Attack_TTP": "T1087.002 - Account Discovery: Domain Account. This technique involves discovering \n"
                              "domain accounts, which can include queries for user data.",
                "Attack_Type": "Reconnaissance. This method, when used by adversaries, is typically part of \n"
                               "reconnaissance activities to gather information about user accounts within a network \n"
                               "or system.",
                "IOC": "High frequency of requests for the invoking security principal's name, potentially part of \n"
                       "reconnaissance activities."
            },
            76: {
                "Method": "lsa_LookupSids3",
                "Note": "Resolving SIDs to account names can map out users and groups for further attacks within \n"
                        "AD environments. \n\n"
                        ""
                        "The LsarLookupSids3 method translates a batch of security principal SIDs to their name forms.\n"
                        "It also returns the domains that these names are a part of. \n\n"
                        ""
                        "Imagine every worker has a unique ID badge. This function takes a bunch of these ID \n"
                        "numbers and matches them to the worker's names and their departments. It's like a reverse \n"
                        "phonebook for employee IDs that helps figure out who these IDs belong to.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Reconnaissance",
                "IOC": "Repeated SID-to-name resolution activities, possibly as part of an effort to map out users \n"
                       "and groups within Active Directory."
            },
            77: {
                "Method": "lsa_LookupNames4",
                "Note": "Translating account names to SIDs can aid in creating Golden Tickets and identifying \n"
                        "targets for escalation. \n\n"
                        ""
                        "The LsarLookupNames4 method translates a batch of security principal names to their SID \n"
                        "form. It also returns the domains of which these security principals are a part. This one \n"
                        "is the opposite of lsa_LookupSids3. Instead of starting with ID badges, you start with \n"
                        "names and this function finds their corresponding ID numbers. It's like looking up the \n"
                        "serial number of a product by its name to find out more information about it.\n\n"
                        ""
                        "This function is a newer, more efficient way of doing what LsarLookupNames does. It's \n"
                        "like having an upgraded office directory that not only tells you the job titles but also \n"
                        "other details like the department and direct line for each employee.",
                "Attack_TTP": "T1558.001 - Golden Ticket",
                "Attack_Type": "Credential Theft and Privilege Escalation",
                "IOC": "Frequent translation of account names to SIDs, which could be preparatory steps for creating\n"
                       "Golden Tickets or identifying escalation targets."
            }
        }
    },
    "netlogon": {
        "UUID": "12345678-1234-abcd-ef00-01234567cffb",
        "Protocol": "Netlogon Remote Protocol - (NRPC) - exploitation of remote services - zerologon - netlogon.dll (loads into) lsass.exe",
        "Version": "1.0",
        "Methods": {
            2: {
                "Method": "NetrLogonSamLogon",
                "Note": "This function is involved in processing user logon requests and is susceptible to brute \n"
                        "force attacks if weak passwords are used. This is like the security guard checking an \n"
                        "employee's ID card when they arrive at work. It's a way for the computer to check with \n"
                        "the network's security system to make sure a user is who they say they are when they try \n"
                        "to log in.\n\n"
                        ""
                        "The NetrLogonSamLogon method is a predecessor to the NetrLogonSamLogonWithFlags method \n"
                        "(section 3.5.4.5.2). All parameters of this method have the same meanings as the \n"
                        "identically named parameters of the NetrLogonSamLogonWithFlags method.",
                "Attack_TTP": "T1110 - Brute Force, T1078, T1557",
                "Attack_Type": "Credential Access via Password Spraying",
                "IOC": "Unusual login patterns or volume, especially from non-standard locations."
            },
            3: {
                "Method": "NetrLogonSamLogoff",
                "Note": "This method manages user logoff requests and can disrupt sessions, potentially being used \n"
                        "for denial-of-service attacks. This is like the security guard logging the time when an \n"
                        "employee leaves. It tells the network's security system that the user is done working and \n"
                        "logs them out, helping to keep the user's account secure when they're not using it. \n\n"
                        ""
                        "The NetrLogonSamLogoff method SHOULD update the user lastLogoff attribute for the SAM \n"
                        "accounts.",
                "Attack_TTP": "T1485 - Data Destruction",
                "Attack_Type": "Denial of Service",
                "IOC": "-Patterns where users are logged off en masse or at unusual times, which could indicate an \n"
                       "attempt to disrupt normal operations. \n"
                       "-Multiple logoff requests for the same user accounts in a short period, especially outside of \n"
                       "usual working hours, could suggest an attempt to disrupt the user's access. \n"
                       "-System or security logs displaying an unusually high number of failed logoff attempts or \n"
                       "errors related to user logoff processes."
            },
            4: {
                "Method": "NetrServerReqChallenge",
                "Note": "Part of the secure channel establishment process, this method is used in the initial stages \n"
                        "of the Zerologon exploit. Imagine this as the security guard asking for a password before \n"
                        "letting someone in. It's a part of the process where the computer and the network's security\n"
                        "system agree on a 'secret handshake' so that they can communicate securely. \n\n"
                        ""
                        "The NetrServerReqChallenge method SHOULD receive a client challenge and return a server \n"
                        "challenge (SC).",
                "Attack_TTP": "T1075 - Pass the Hash, T1557, T1558",
                "Attack_Type": "Credential Access via Zerologon",
                "IOC": "Irregular traffic patterns or anomalous requests to domain controllers."
            },
            31: {
                "Method": "NetrServerPasswordGet",
                "Note": "This method can be exploited to retrieve machine account passwords, aiding in lateral \n"
                        "movement or privilege escalation. This is like a manager asking the guard for the keys to \n"
                        "a locked office. It's a function that allows a server to retrieve the stored password or \n"
                        "a related secret for a computer or user, which is necessary for verifying identity and \n"
                        "maintaining security.\n\n"
                        ""
                        "The NetrServerPasswordGet method SHOULD allow a BDC to get a machine account password \n"
                        "from the DC with the PDC role in the domain.",
                "Attack_TTP": "T1003 - Credential Dumping, T1003, T1078",
                "Attack_Type": "Lateral Movement",
                "IOC": "Unusual access to password-related information on the server."
            },
            7: {
                "Method": "NetrDatabaseDeltas",
                "Note": "Used in domain replication, this method can be co-opted by attackers to intercept \n"
                        "sensitive replication data. This function is like a security guard checking what has \n"
                        "changed in the personnel files since the last check. It lists the recent changes made \n"
                        "to user accounts or security policies within the network.\n\n"
                        ""
                        "The NetrDatabaseDeltas method SHOULD return a set of changes (or deltas) performed to \n"
                        "the SAM database, SAM built-in database, or LSA databases after a particular value of \n"
                        "the database serial number. It is used by BDCs to request database changes from the PDC \n"
                        "that are missing on the BDC.",
                "Attack_TTP": "T1107 - File Deletion",
                "Attack_Type": "Defense Evasion by Deleting Evidence"
            },
            26: {
                "Method": "NetrServerAuthenticate3",
                "Note": "Central to the Zerologon attack, this method can be used to bypass authentication controls \n"
                        "by changing the machine password. Imagine a security checkpoint where guards verify the \n"
                        "identity of a person before letting them into a secure area. This function is the computer \n"
                        "equivalent, where a server checks to make sure another server or computer is who it claims \n"
                        "to be before allowing access to secure resources. \n\n"
                        ""
                        "The NetrServerAuthenticate3 method SHOULD mutually authenticate the client and the server \n"
                        "and establish the session key to be used for the secure channel message protection between \n"
                        "the client and the server. It is called after the NetrServerReqChallenge method.",
                "Attack_TTP": "T1557 - Man-in-the-Middle, T1557, T1558",
                "Attack_Type": "Credential Access and Defense Evasion",
                "IOC": "Anomalies in authentication logs, such as unexpected spikes in activity."
            },
            42: {
                "Method": "NetrServerTrustPasswordsGet",
                "Note": "This method can be abused to retrieve inter-domain trust passwords, potentially compromising\n"
                        "the entire AD forest. This could be likened to a higher-up security officer who has the \n"
                        "authority to access the master keys or passwords for various doors in the building. The \n"
                        "function retrieves special passwords (trust passwords) that are used by domain controllers \n"
                        "to establish secure communication with each other.\n\n"
                        ""
                        "The NetrServerTrustPasswordsGet method SHOULD return the encrypted current and previous \n"
                        "passwords for an account in the domain. This method is called by a client to retrieve \n"
                        "the current and previous account passwords from a domain controller. The account name \n"
                        "requested MUST be the name used when the secure channel was created, unless the method \n"
                        "is called on a PDC by a DC, in which case it can be any valid account name.",
                "Attack_TTP": "T1482 - Domain Trust Discovery, T1003, T1078",
                "Attack_Type": "Discovery and Lateral Movement",
                "IOC": "Access patterns to sensitive trust password information that deviate from the norm."
            },
            29: {
                "Method": "NetrLogonGetDomainInfo",
                "Note": "Can be used for extensive domain reconnaissance, potentially aiding in credential-based \n"
                        "attacks like pass-the-hash. The NetrLogonGetDomainInfo method SHOULD return information that\n"
                        "describes the current domain to which the specified client belongs.",
                "Attack_TTP": "T1087 - Account Discovery, T1087, T1016",
                "Attack_Type": "Discovery and Credential Access",
                "IOC": "Unusual queries for domain information that could indicate reconnaissance activities."
            },
            30: {
                "Method": "NetrServerPasswordSet2",
                "Note": "This method is abused post-exploitation to alter machine account passwords, taking over \n"
                        "the machine's domain identity. \n\n"
                        ""
                        "The NetrServerPasswordSet2 method SHOULD allow the client to set a new clear text password \n"
                        "for an account used by the domain controller for setting up the secure channel from the \n"
                        "client. A domain member SHOULD use this function to periodically change its machine account \n"
                        "password. A PDC uses this function to periodically change the trust password for all \n"
                        "directly trusted domains.",
                "Attack_TTP": "T1098 - Account Manipulation, T1557.001, T1558",
                "Attack_Type": "Persistence and Privilege Escalation",
                "IOC": "Unauthorized modifications of passwords or security relationships on the server."
            },
            34: {
                "Method": "DsrGetDcNameEx2",
                "Note": "Often used for gathering information about domain controllers, this method can be a \n"
                        "precursor to a DCSync attack. \n\n"
                        ""
                        "The DsrGetDcNameEx2 method SHOULD return information about a domain controller (DC) in the \n"
                        "specified domain and site. If the AccountName parameter is not NULL, and a DC matching the \n"
                        "requested capabilities (as defined in the Flags parameter) responds during this method call,\n"
                        "then that DC will have verified that the DC account database contains an account for the \n"
                        "AccountName specified. The server that receives this call is not required to be a DC.",
                "Attack_TTP": "T1087 - Account Discovery, T1018, T1046",
                "Attack_Type": "Discovery for DCSync Attack",
                "IOC": "Unusual network scanning activities, particularly targeted at domain controllers."
            },
            40: {
                "Method": "DsrEnumerateDomainTrusts",
                "Note": "The DsrEnumerateDomainTrusts method SHOULD return an enumerated list of domain trusts, \n"
                        "filtered by a set of flags, from the specified server.",
                "Attack_TTP": "T1482, T1016",
                "Attack_Type": "",
                "IOC": "Excessive enumeration of domain trusts, which could be a sign of an adversary mapping the network."
            },
            46: {
                "Method": "NetrServerGetTrustInfo",
                "Note": "This method can be misused to forge inter-realm trust tickets, commonly known as Silver \n"
                        "Ticket attacks. \n\n"
                        ""
                        "The NetrServerGetTrustInfo method SHOULD return an information block from a specified \n"
                        "server. The information includes encrypted current and previous passwords for a particular \n"
                        "account and additional trust data. The account name requested MUST be the name used when \n"
                        "the secure channel was created, unless the method is called on a PDC by a domain controller,\n"
                        "in which case it can be any valid account name.",
                "Attack_TTP": "T1558.002 - Silver Ticket, T1482, T1201",
                "Attack_Type": "Credential Access and Persistence",
                "IOC": "Suspicious activities around domain trust relationships, possibly indicating efforts to map\n"
                       "trust policies."
            },
            45: {
                "Method": "NetrLogonSamLogonWithFlags",
                "Note": "This extended logon method may be vulnerable to similar attacks as NetrLogonSamLogon, \n"
                        "with added flag manipulation risks. \n\n"
                        ""
                        "The NetrLogonSamLogonWithFlags method SHOULD handle logon requests for the SAM accounts.",
                "Attack_TTP": "T1110 - Brute Force, T1078, T1557",
                "Attack_Type": "Credential Access via Password Spraying",
                "IOC": "Sudden changes in user privileges or access patterns."
            },
            39: {
                "Method": "NetrLogonSamLogonEx",
                "Note": "This enhanced logon function could be exploited for unauthorized access, potentially \n"
                        "enabling more sophisticated attacks. \n\n"
                        ""
                        "The NetrLogonSamLogonEx method SHOULD provide an extension to NetrLogonSamLogon that \n"
                        "accepts an extra flags parameter and uses Secure RPC ([MS-RPCE] section 3.3.1.5.2) instead \n"
                        "of Netlogon authenticators. This method handles logon requests for the SAM accounts and \n"
                        "allows for generic pass-through authentication.",
                "Attack_TTP": "T1110 - Brute Force, T1078, T1557",
                "Attack_Type": "Credential Access via Password Spraying",
                "IOC": "Multiple failed authentication attempts, suggesting brute force or password spraying attempts."
            }
        }
    },
    "samr": {
        "UUID": "12345778-1234-ABCD-EF00-0123456789AC",
        "Protocol": "Security Account Manager (SAM) Remote Protocol (MS-SAMR) - samsrv.dll (loads into) lsass.exe",
        "Version": "1.0",
        "Methods": {
            6: {
                "Method": "SamrEnumerateDomainsInSamServer",
                "Note": "Can be used by attackers to map out Active Directory domains within an organization, \n"
                        "understanding its structure for further attacks.\n\n"
                        ""
                        "The SamrEnumerateDomainsInSamServer method obtains a listing of all domains hosted by the \n"
                        "server side of this protocol. It's like asking for a complete list of all the departments in\n"
                        "a large company. ",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Numerous or repeated queries to enumerate domain names in a network."
            },
            5: {
                "Method": "SamrLookupDomainInSamServer",
                "Note": "May be used to resolve domain names to SIDs, aiding in lateral movement and privilege \n"
                        "escalation strategies by attackers.\n\n"
                        ""
                        "Used to find the unique identifier (known as the Security Identifier, or SID) for a \n"
                        "specific domain based on the domain's name. This is akin to looking up a specific \n"
                        "department's internal code by its name.",
                "Attack_TTP": "T1069 - Permission Groups Discovery",
                "Attack_Type": "Privilege Escalation",
                "IOC": "Repeated queries to resolve domain names to SIDs."
            },
            17: {
                "Method": "SamrLookupNamesInDomain",
                "Note": "Translating usernames to RIDs can help in account compromise by linking usernames to \n"
                        "specific domain accounts.\n\n"
                        ""
                        "Translates a set of account names into a set of RIDs.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Credential Access",
                "IOC": "Frequent translation requests from usernames to RIDs."
            },
            13: {
                "Method": "SamrEnumerateUsersInDomain",
                "Note": "Used to enumerate user accounts, which can be exploited by threat actors to identify \n"
                        "targets for credential theft.\n\n"
                        ""
                        "Enumerates all users.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Credential Access",
                "IOC": "Multiple queries to list all user accounts in a domain."
            },
            7: {
                "Method": "SamrOpenDomain",
                "Note": "Allows establishing a session with a domain object, potentially for reconnaissance or \n"
                        "domain object modifications.\n\n"
                        ""
                        "Obtains a handle to a domain object, given a SID.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Attempts to open multiple domain objects in quick succession."
            },
            8: {
                "Method": "SamrQueryInformationDomain",
                "Note": "Could be used to extract domain policies, informing attackers on how to tailor their \n"
                        "attacks, like password spraying.\n\n"
                        ""
                        "Obtains attributes from a domain object.",
                "Attack_TTP": "T1201 - Password Policy Discovery",
                "Attack_Type": "Credential Access",
                "IOC": "Queries to access domain policies or attributes."
            },
            34: {
                "Method": "SamrOpenUser",
                "Note": "Opening user objects can allow attackers to gather detailed information or modify \n"
                        "attributes for persistence or privilege escalation.\n\n"
                        ""
                        "Obtains a handle to a user, given a RID.",
                "Attack_TTP": "T1087 - Account Discovery",
                "Attack_Type": "Persistence",
                "IOC": "Repeated requests to obtain handles to various user accounts."
            },
            36: {
                "Method": "SamrQueryInformationUser",
                "Note": "Querying for user information such as last logon times can be used for targeting active \n"
                        "users in phishing or other campaigns.\n\n"
                        ""
                        "Obtains attributes from a user object.",
                "Attack_TTP": "T1078 - Valid Accounts, T1087: Account Discovery",
                "Attack_Type": "Credential Access",
                "IOC": "Frequent requests for detailed user account information."
            },
            25: {
                "Method": "SamrGetMembersInGroup",
                "Note": "Identifying group memberships, particularly administrative ones, can aid attackers in \n"
                        "targeting privileged accounts for attacks.\n\n"
                        ""
                        "Reads the members of a group.",
                "Attack_TTP": "T1069 - Permission Groups Discovery",
                "Attack_Type": "Privilege Escalation",
                "IOC": "Queries to obtain group membership details, especially for administrative or sensitive groups."
            },
            38: {
                "Method": "SamrChangePasswordUser",
                "Note": "The SamrChangePasswordUser method changes the password of a user object.",
                "Attack_TTP": "T1003: OS Credential Dumping",
                "Attack_Type": "Credential Dumping",
                "IOC": "Attempts to change user passwords, especially if targeting multiple accounts or \n"
                       "privileged users."
            }
        }
    },
    "srvsvc": {
        "UUID": "4b324fc8-1670-01d3-1278-5a47bf6ee188",
        "Protocol": "SRVSVC - System Enumeration - srvsvc.dll (loads into) svchost.exe",
        "Version": "3.0",
        "Methods": {
            15: {
                "Method": "NetrShareEnum",
                "Note": "Can be used by APT groups to enumerate network shares for lateral movement and data \n"
                        "harvesting.\n\n"
                        ""
                        "Retrieves a list of all shared resources on a server. Think of it as asking the server for \n"
                        "a complete catalog of everything it's currently sharing with others. This could include \n"
                        "shared folders, printers, and other resources that are available on the network for use by \n"
                        "authorized individuals.\n\n"
                        ""
                        "The NetrShareEnum method retrieves information about each shared resource on a server.",
                "Attack_TTP": "T1135 - Network Share Discovery",
                "Attack_Type": "Discovery and Lateral Movement",
                "IOC": "Unusual network share enumeration requests, especially from unexpected sources or at odd times."
            },
            16: {
                "Method": "NetrShareGetInfo",
                "Note": "May be used by adversaries to gather detailed information about specific network shares.\n\n"
                        ""
                        "More specific than NetrShareEnum. Gets detailed information about a particular shared \n"
                        "resource from the server. It's like looking up detailed information about one item in \n"
                        "the catalog, such as who can access a specific shared folder and what permissions they have.\n"
                        ""
                        "Retrieves information about a particular shared resource on the server from the ShareList.",
                "Attack_TTP": "T1082 - System Information Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Specific queries for information on particular network shares, outside of regular \n"
                       "administrative activity."
            },
            12: {
                "Method": "NetrSessionEnum",
                "Note": "Could be leveraged by attackers to gather information on active user sessions for targeted \n"
                        "attacks or scope access.\n\n"
                        ""
                        "Provides information about sessions that are established on a server. A session is created \n"
                        "when a user or a computer connects to another computer on the network to access shared \n"
                        "resources. This function could be used to get a list of all such connections, which includes\n"
                        "details about the users who are connected and the computers they're connecting from.\n\n"
                        ""
                        "The NetrSessionEnum method MUST return information about sessions that are established on a \n"
                        "server or return an error code.",
                "Attack_TTP": "T1049 - System Network Connections Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Excessive session enumeration requests which might indicate an attempt to map active \n"
                       "connections and user sessions."
            },
            13: {
                "Method": "NetrSessionDel",
                "Note": "Might be used by threat actors to remove sessions and cover tracks after data exfil.\n\n"
                        ""
                        "The NetrSessionDel method MUST end one or more network sessions between a server and a \n"
                        "client.",
                "Attack_TTP": "T1070 - Indicator Removal on Host",
                "Attack_Type": "Defense Evasion",
                "IOC": "Unexpected termination of user sessions, potentially disrupting normal operations or hiding \n"
                       "unauthorized access."
            },
            9: {
                "Method": "NetrFileEnum",
                "Note": "Can be abused to monitor file usage patterns and identify critical assets for attack planning.\n\n"
                        ""
                        "The NetrFileEnum method MUST return information about some or all open files on a server, \n"
                        "depending on the parameters specified, or return an error code.",
                "Attack_TTP": "T1083 - File and Directory Discovery",
                "Attack_Type": "Discovery",
                "IOC": "Abnormal patterns of file access queries, which might indicate an adversary trying to locate \n"
                       "specific files or directories."
            },
            11: {
                "Method": "NetrFileClose",
                "Note": "If abused, this could be used to interfere with critical processes or alter files, \n"
                        "potentially in ransomware attacks.\n\n"
                        ""
                        "The server receives the NetrFileClose method in an RPC_REQUEST packet. In response, the \n"
                        "server MUST force an open resource instance (for example, file, device, or named pipe) on \n"
                        "the server to close. This message can be used when an error prevents closure by any other \n"
                        "means.",
                "Attack_TTP": "T1489 - Service Stop",
                "Attack_Type": "Impact",
                "IOC": "Unusual closing of files, especially those critical to system or application functionality, \n"
                       "which could disrupt services."
            },
            14: {
                "Method": "NetrShareAdd",
                "Note": "Exploitable by APTs to create network shares for data exfiltration or persistent access.\n\n"
                        ""
                        "The NetrShareAdd method shares a server resource.",
                "Attack_TTP": "T1135 - Network Share Discovery",
                "Attack_Type": "Persistence and Lateral Movement",
                "IOC": "Creation of new network shares that are not in line with standard IT practices or business \n"
                       "needs."
            },
            18: {
                "Method": "NetrShareDel",
                "Note": "Could be used post-compromise to remove evidence of unauthorized network shares.\n\n"
                        ""
                        "The NetrShareDel method deletes a share name from the ShareList, which disconnects all \n"
                        "connections to the shared resource. If the share is sticky, all information about the share \n"
                        "is also deleted from permanent storage.",
                "Attack_TTP": "T1070 - Indicator Removal on Host",
                "Attack_Type": "Defense Evasion",
                "IOC": "Deletion of network shares, possibly in an effort to cover tracks after data exfiltration or \n"
                       "unauthorized access."
            },
            17: {
                "Method": "NetrShareSetInfo",
                "Note": "May be exploited to change share permissions, allowing unauthorized data access.\n\n"
                        ""
                        "The NetrShareSetInfo method sets the parameters of a shared resource in a ShareList.",
                "Attack_TTP": "T1222 - File and Directory Permissions Modification",
                "Attack_Type": "Privilege Escalation",
                "IOC": "Changes to network share permissions or settings, particularly those granting wider access or\n"
                       "reducing security controls."
            }
        }
    },
    "winreg": {
        "UUID": "338cd001-2244-31f1-aaaa-900038001003",
        "Protocol": "Remote Management and Monitoring (WinReg)",
        "Version": "1.0",
        "Methods": {
            2: {
                "Method": "OpenHKLM",
                "Note": "Provides access to system-wide settings and configurations through the HKLM hive.",
                "Attack_TTP": "T1112 - Modify Registry",
                "Attack_Type": "Persistence, Privilege Escalation, and Configuration Tampering",
                "IOC": "Unauthorized registry changes in HKLM hive, unusual remote access to HKLM hive, unexpected \n"
                       "system-wide changes in configurations."
            },
            5: {
                "Method": "OpenHKU",
                "Note": "Allows for changes to user profiles via the HKU hive, potentially for persistence or \n"
                        "configuration tampering.",
                "Attack_TTP": "T1112 - Modify Registry",
                "Attack_Type": "Persistence and Privilege Escalation",
                "IOC": "Changes in user profiles that are unexplained or unauthorized, unusual access patterns to \n"
                       "HKU hive."
            },
            22: {
                "Method": "RegSetValue",
                "Note": "Enables modification of registry keys and values, as seen in malware like Stuxnet for \n"
                        "propagation and system configuration changes.",
                "Attack_TTP": "T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "Attack_Type": "Persistence, Privilege Escalation, and System Compromise",
                "IOC": "Creation of unusual or suspicious registry keys and values, particularly in startup or \n"
                       "run keys."
            },
            6: {
                "Method": "RegCreateKey",
                "Note": "Can be used to create new registry keys for storing data or establishing persistence.",
                "Attack_TTP": "T1136 - Create Account",
                "Attack_Type": "Persistence via New Account Creation",
                "IOC": "Creation of new, unexpected registry keys, possibly with unusual names or in unusual locations."
            },
            8: {
                "Method": "RegDeleteKey",
                "Note": "Potential for removing evidence of presence or disrupting system/application functionality.",
                "Attack_TTP": "T1485 - Data Destruction",
                "Attack_Type": "Defense Evasion by Removing Evidence",
                "IOC": "Deletion of registry keys that are critical for system or application functionality, unusual\n"
                       "patterns of registry key deletions."
            },
            9: {
                "Method": "RegEnumKey",
                "Note": "Allows enumeration of subkeys, which can be used for reconnaissance of potential \n"
                        "exploitation targets.",
                "Attack_TTP": "T1082 - System Information Discovery",
                "Attack_Type": "Discovery and Reconnaissance",
                "IOC": "Unusual, systematic enumeration of registry keys, particularly sensitive system or \n"
                       "application keys."
            },
            10: {
                "Method": "RegEnumValue",
                "Note": "Enables enumeration of registry values for scouting configuration settings or evidence \n"
                        "of other malware.",
                "Attack_TTP": "T1012 - Query Registry",
                "Attack_Type": "Discovery and Information Gathering",
                "IOC": "Systematic scanning or enumeration of registry values, especially if correlated with other \n"
                       "suspicious activities."
            }
        }
    },
    "references": {
        "url1": "https://github.com/jsecurity101/MSRPC-to-ATTACK/tree/main",
        "samr": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/"
                "e8205d2c-9ebb-4845-b927-0aca7cbc1f2c",
        "drsuapi": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/"
                   "58f33216-d9f1-43bf-a183-87e3c899c410",
        "lsarpc": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/"
                  "86f5e73b-98c4-4234-89cb-d9ff5f327b73"
    }
}


if __name__ == '__main__':
    pass
