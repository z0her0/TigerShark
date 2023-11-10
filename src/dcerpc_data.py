#dcerpc_data.py

# The `dcerpc_services` dictionary is a comprehensive map of several DCERPC services, their UUIDs, descriptions,
# versions, and associated methods along with operation numbers (opnums). This data structure can be utilized to
# identify and understand potential vulnerabilities or common attack patterns by APTs (Advanced Persistent Threats).
# Each service in the dictionary details specific RPC methods that may be targeted by APTs, with a focus on methods
# known to be exploited historically or which may pose potential security risks.

dcerpc_services = {
    "summary": {
        "overview": "Think of these protocols like different specialized tools in a toolbox, each with a specific "
                    "function in building and maintaining a house.",
        "dcerpc": "Distributed Computing Environment/Remote Procedure Call. This is the toolbox itself. It's a set "
                  "of rules that allows software programs to communicate over a network. Just like a toolbox that "
                  "holds various tools, DCERPC holds various protocols that help different parts of a network talk "
                  "to each other.",
        "ms_nrpc": "Netlogon Remote Protocol. This tool is like the security system of the house. It helps to "
                   "verify the identities of the 'residents' (users) and make sure that they are who they say "
                   "they are when they try to 'enter' (log in).",
        "ms_drsr": "Directory Replication Service. This is like the mail delivery system ensuring that all "
                   "residents get their mail. It replicates directory information, like user data and security "
                   "permissions, across different 'houses' (servers) to make sure everyone has up-to-date "
                   "information.",
        "ms_lsad": "Local Security Authority Remote Protocol. Consider this as the internal rules of the "
                   "house that manage who is allowed to do what. It deals with policies related to security "
                   "and permissions within a computer.",
        "ms_srvs": "Server Service Remote Protocol. This is like the maintenance crew who takes care of "
                   "sharing resources like printers or files over the network, similar to shared spaces in "
                   "a housing complex.",
        "ms_samr": "Security Account Manager Remote Protocol. This is like the human resources department "
                   "that manages employee records. It handles the details of security accounts, like users "
                   "and their passwords."
    },
    "drsuapi": {
        "UUID": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
        "Protocol": "MS-DRSR (Directory Replication Service) interface - DCSync, Rogue Domain Controller",
        "Version": "4.0",
        "Methods": {
            0: {
                "Method": "IDL_DRSBind",
                "Note": "The IDL_DRSBind method creates a context handle that is necessary to call any other "
                        "method in this interface. This is like introducing yourself when you pick up the phone "
                        "and start a conversation."
                        ""
                        "In a computer network, IDL_DRSBind is used to start a session between two systems that want "
                        "to communicate about replication. It's the way a computer says 'Hello, I'd like to talk "
                        "about keeping our user and computer information in sync,' to which the other system responds "
                        "by establishing a connection for them to communicate securely.",
                "ATT&CK TTP": "T1078 - Valid Accounts",
                "Attack Type": "Persistence, Privilege Escalation, Initial Access",
                "Detects": "Monitor for newly constructed logon behavior that may obtain and abuse credentials of "
                           "existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation,"
                           " or Defense Evasion. Correlate other security systems with login information (e.g., a user"
                           " has an active login session but has not entered the building or does not have VPN access).",
                "Detection ID": "https://attack.mitre.org/datasources/DS0028"
            },
            1: {
                "Method": "IDL_DRSUnbind",
                "Note": "The IDL_DRSUnbind method destroys a context handle previously created by the IDL_DRSBind"
                        " method. This is the equivalent of saying 'Goodbye' at the end of a phone call. After two "
                        "systems have finished communicating about replication, IDL_DRSUnbind is used to end the "
                        "session. It's like one computer saying, 'Our conversation is finished, let's hang up the "
                        "line,' and the connection is closed properly.",
                "ATT&CK TTP": "T1078 - Valid Accounts",
                "Attack Type": "Persistence, Privilege Escalation, Initial Access",
                "Detects": "",
                "Detection ID": ""
            },
            2: {
                "Method": "IDL_DRSReplicaSync",
                "Note": "Triggers replication from another DC, which could be used in a DCSync attack to spread "
                        "malicious changes rapidly. This is like a request to immediately send out any new updates or"
                        " changes. It's like calling a friend and saying, 'Hey, if you have any new news, tell me now!'"
                        " It's a way to ensure that a computer has the latest information without waiting for the "
                        "regular update schedule.",
                "ATT&CK TTP": "T1003.006 - DCSync",
                "Attack Type": "Credential Access and Lateral Movement",
                "Detects": "",
                "Detection ID": ""
            },
            3: {
                "Method": "IDL_DRSGetNCChanges",
                "Note": "Replicates updates from an NC replica on the server. "
                        ""
                        "This function is exploited in DCSync attacks to mimic a DC and retrieve directory "
                        "information. "
                        ""
                        "So, IDL_DRSReplicaSync is about triggering an update across the network, and "
                        "IDL_DRSGetNCChanges is about getting the specifics of what has changed. They work together "
                        "to keep the entire network in sync and up-to-date.",
                "ATT&CK TTP": "T1003.006 - DCSync",
                "Attack Type": "Credential Access via Directory Replication",
                "Detects": "",
                "Detection ID": ""
            },
            4: {
                "Method": "IDL_DRSUpdateRefs",
                "Note": "Updates replication references, which could be misused to add a rogue DC or disrupt "
                        "legitimate replication. "
                        ""
                        "Adds or deletes a value from the repsTo of a specified NC replica."
                        ""
                        "This function is like updating the contact list on your phone. It manages references to "
                        "other computers that should receive updates. It's like telling your phone which friends to"
                        " keep in the loop about your news.",
                "ATT&CK TTP": "T1484.002 - Domain Trust Modification",
                "Attack Type": "Persistence and Defense Evasion",
                "Detects": "",
                "Detection ID": ""
            },
            5: {
                "Method": "IDL_DRSReplicaAdd",
                "Note": "Adds a replication source reference for the specified NC. "
                        ""
                        "Can introduce a rogue Domain Controller to the replication process, allowing for "
                        "unauthorized AD alterations. This is like setting up a new delivery route in a postal "
                        "system. "
                        ""
                        "When you use this function, you're telling one server to start sharing information with "
                        "another server that it wasn't talking to before. It's like saying, 'Hey, start sending "
                        "copies of your files and updates over to this new server so it stays up-to-date with what's "
                        "happening.'",
                "ATT&CK TTP": "T1207 - Rogue Domain Controller",
                "Attack Type": "Persistence and Privilege Escalation",
                "Detects": "",
                "Detection ID": ""
            },
            6: {
                "Method": "IDL_DRSReplicaDel",
                "Note": "Removes replication sources, which could be used post-DCShadow attack to erase evidence "
                        "of unauthorized changes."
                        ""
                        "This function is the opposite of IDL_DRSReplicaAdd; it's like canceling a delivery route. "
                        "You're telling a server to stop sending its information to another server. It's like "
                        "telling the post office to stop delivering mail to an address because it's no longer in use "
                        "or needed.",
                "ATT&CK TTP": "T1070.004 - File Deletion",
                "Attack Type": "Defense Evasion",
                "Detects": "",
                "Detection ID": ""
            },
            7: {
                "Method": "IDL_DRSReplicaModify",
                "Note": "Modifies replication settings, potentially to evade defenses or maintain unauthorized "
                        "access within an environment. Specifically, it's a function used in Windows Active "
                        "Directory environments that allows changes to be made to how domain controllers replicate"
                        " directory information among each other. "
                        ""
                        "This function is a part of the internal workings of Active Directory that helps "
                        "administrators or the system itself to manage the replication topology—the 'map' that "
                        "defines which controller talks to which and how often they exchange updates to ensure all of "
                        "them have the latest data."
                        ""
                        "This one is more like setting up a schedule for when you call your friends and what topics "
                        "you'll talk about. It adjusts the details of how and when computers in the network sync up "
                        "their information.",
                "ATT&CK TTP": "T1484.002 - Domain Trust Modification",
                "Attack Type": "Persistence and Defense Evasion",
                "Detects": "",
                "Detection ID": ""
            },
            8: {
                "Method": "IDL_DRSVerifyNames",
                "Note": "Resolves a sequence of object identities. "
                        ""
                        "Can verify the existence of AD objects, which may be part of advanced reconnaissance before "
                        "targeted attacks. "
                        ""
                        "This is like a verification service at a club who checks your ID to make sure you are who "
                        "you say you are before letting you in. In the context of a computer network, it checks the "
                        "names (like usernames or computer names) to confirm they exist and are correct within the "
                        "network's directory, which is like the club's guest list.",
                "ATT&CK TTP": "T1087.002 - Account Discovery: Domain Account",
                "Attack Type": "Discovery",
                "Detects": "",
                "Detection ID": ""
            },
            9: {
                "Method": "IDL_DRSGetMemberships",
                "Note": "Retrieves group membership for an object. Think of this as a club membership manager who "
                        "has a list of all the clubs each person belongs to. When someone wants to know what clubs a "
                        "user is a part of, this function provides that information. It tells you every group or "
                        "club within the network that the user is a member of.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Discovery",
                "Detects": "Monitor for an extracted list of ACLs of available groups and/or their associated settings.",
                "Detection ID": "https://attack.mitre.org/datasources/DS0036"
            },
            10: {
                "Method": "IDL_DRSInterDomainMove",
                "Note": "Helper method used in a cross-NC move LDAP operation. "
                        ""
                        "This is like a moving service for user accounts. Imagine you have an account at a library "
                        "in one town and you move to another town. This service would transfer your account to your "
                        "new local library so you can borrow books there without creating a new account. In "
                        "technical terms, this function helps move an account from one domain to another within the "
                        "same forest (a collection of connected domains). It ensures that the account retains its "
                        "history and rights in the new domain.",
                "ATT&CK TTP": "T1105 - Ingress Tool Transfer",
                "Attack Type": "Lateral Movement",
                "Detects": "Monitor executed commands and arguments for suspicious activity associated with "
                           "downloading external content.",
                "Detection ID": "https://attack.mitre.org/datasources/DS0017"
            },
            11: {
                "Method": "IDL_DRSGetNT4ChangeLog",
                "Note": "If the server is the PDC emulator FSMO role owner, the IDL_DRSGetNT4ChangeLog "
                        "method returns either a sequence of PDC change log entries or the NT4 replication state, "
                        "or both, as requested by the client. "
                        ""
                        "This is like a history book or a log that keeps track of all the changes made in the "
                        "network related to user accounts and passwords, but specifically from old Windows NT 4.0 "
                        "systems. It's a way to look back at what has been done, which can be important for "
                        "understanding changes or for troubleshooting issues.",
                "ATT&CK TTP": "T1133 - External Remote Services",
                "Attack Type": "Persistence, Initial Access",
                "Detects": "Monitor for unusual access patterns to remote services, such as activity during odd hours.",
                "Detection ID": "https://attack.mitre.org/datasources/DS0028"
            },
            12: {
                "Method": "IDL_DRSCrackNames",
                "Note": "Translates object names for replication changes, potentially used in reconnaissance to "
                        "map domain resources."
                        ""
                        "IDL_DRSCrackNames helps ensure that when changes are made to objects in the directory "
                        "(like a user getting a new job title or a computer being moved to a new organizational unit), "
                        "these changes are correctly understood and distributed across the network, so all the domain "
                        "controllers have the same, updated information about these objects. It's a bit like a "
                        "translator that makes sure everyone is speaking the same language when they talk about who "
                        "or what is in the network and any updates to it.",
                "ATT&CK TTP": "T1087.002 - Account Discovery: Domain Account",
                "Attack Type": "Discovery",
                "Detects": "",
                "Detection ID": ""
            },
            13: {
                "Method": "IDL_DRSWriteAccountSpn",
                "Note": "Updates the set of SPNs on an object. "
                        ""
                        "Writing SPNs could be abused in a Kerberoasting attack to gain access to service account "
                        "credentials. "
                        ""
                        "This function is like a labeling machine for user accounts. SPN stands for Service Principal"
                        " Name, which is essentially a unique identifier for a service on a network. By modifying "
                        "SPNs, this function can change the labels attached to user accounts, which can affect how "
                        "users or services prove their identity on the network. If someone changes these labels "
                        "incorrectly or maliciously, it could allow unauthorized access to network services.",
                "ATT&CK TTP": "T1558.003 - Kerberoasting",
                "Attack Type": "Credential Access",
                "Detects": "",
                "Detection ID": ""
            },
            14: {
                "Method": "IDL_DRSRemoveDsServer",
                "Note": "Removes the representation (also known as metadata) of a DC from the directory. "
                        ""
                        "Imagine you have a bunch of managers (servers) in a big company (the network), and each "
                        "manager has a specific role. Now, if the company decides that one of the managers is no "
                        "longer needed, it uses a process (this function) to officially remove that manager from "
                        "their role. In network terms, this function is used to remove a domain controller (a server "
                        "that manages network security and user information) from the network.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            15: {
                "Method": "IDL_DRSRemoveDsDomain",
                "Note": "Removes the representation (also known as metadata) of a domain from the directory. "
                        ""
                        "Think of a company with different departments (domains). If the company decides to "
                        "completely shut down a whole department, it would use a specific process (this function) "
                        "to do so. In the context of a network, this function is used to remove an entire domain, "
                        "which is a subdivision within an Active Directory environment. This could mean taking down "
                        "all the management and infrastructure related to a particular subset of the network.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            16: {
                "Method": "IDL_DRSDomainControllerInfo",
                "Note": "Retrieves information about DCs in a given domain. "
                        ""
                        "Used to identify Domain Controllers, its unusual use might indicate reconnaissance by an "
                        "APT group. "
                        ""
                        "This function is like asking the HR department for a list of all the managers (domain "
                        "controllers) and their departments (domains) across the company, including details about "
                        "their roles and responsibilities. It's a way to get an overview of who's who and which "
                        "department they're overseeing. The 'opnum' here is like a different form number for this "
                        "type of request.",
                "ATT&CK TTP": "T1018 - Remote System Discovery",
                "Attack Type": "Discovery",
                "Detects": "",
                "Detection ID": ""
            },
            17: {
                "Method": "IDL_DRSAddEntry",
                "Note": "This function can add or modify AD objects, potentially exploited by APTs to create "
                        "backdoors or escalate privileges. "
                        ""
                        "Think of this function as a way to add new entries into a phone book. It's used to create "
                        "new objects, like user or computer accounts, in the Active Directory database. If used "
                        "improperly, it could allow someone to insert false or unauthorized entries into the "
                        "network's 'phone book,' which could be used for malicious purposes like creating fake user "
                        "accounts.",
                "ATT&CK TTP": "T1136.002 - Create Account: Domain Account",
                "Attack Type": "Persistence, Privilege Escalation, and Initial Access",
                "Detects": "",
                "Detection ID": ""
            },
            18: {
                "Method": "IDL_DRSExecuteKCC",
                "Note": "Validates the replication interconnections of DCs and updates them if necessary. "
                        ""
                        "This function is like calling a network technician to optimize your office's internet "
                        "network. It triggers a process that checks and organizes the best paths for communication "
                        "between servers that manage logins and data security in a company's computer network. It's "
                        "like ensuring that all the cables and Wi-Fi signals are arranged for the best speed and "
                        "efficiency, so information flows smoothly and reliably.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            19: {
                "Method": "IDL_DRSGetReplInfo",
                "Note": "Retrieves the replication state of the server. "
                        ""
                        "This function is akin to asking for a detailed report on how the mail has been moving "
                        "around in your office. It provides information about how data is being shared and "
                        "synchronized between the servers in charge of keeping user information and security "
                        "settings up-to-date. If you're managing the network, this report would tell you if "
                        "everything is being shared correctly or if there are any delays or problems.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            20: {
                "Method": "IDL_DRSAddSidHistory",
                "Note": "Adds one or more SIDs to the sIDHistory attribute of a given object. "
                        ""
                        "Imagine you've got a user who's moving from one department to another and you want to make "
                        "sure they can still access their old files as well as the new ones. IDL_DRSAddSidHistory is "
                        "like updating their keycard so it works on doors in both departments. It adds a user's old "
                        "identification from a previous domain to their new account in another domain, so they "
                        "can access resources from both without issue.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            21: {
                "Method": "IDL_DRSGetMemberships2",
                "Note": "Retrieves group memberships for a sequence of objects. "
                        ""
                        "Think about when someone needs to know what clubs or groups a person belongs to within "
                        "a company. IDL_DRSGetMemberships2 is like looking up all the teams and committees a person "
                        "is a part of. This function checks which groups a user is a member of, which can help in "
                        "giving them the correct access to files and systems they need for those groups.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Discovery",
                "Detects": "Monitor for contextual data about a group which describes group and activity around it.",
                "Detection ID": "https://attack.mitre.org/datasources/DS0036"
            },
            22: {
                "Method": "IDL_DRSReplicaVerifyObjects",
                "Note": "Verifies the existence of objects in an NC replica by comparing against a replica "
                        "of the same NC on a reference DC, optionally deleting any objects that do not exist "
                        "on the reference DC. "
                        ""
                        "Think of Active Directory as a city's information center where all the details about its "
                        "citizens and their roles are stored. Imagine this function as a quality checker in the "
                        "information center. It's like having someone go through the records to make sure no false "
                        "information has been added. If the city had a fake citizen added to its records, this tool "
                        "would help find and remove that false entry. This ensures that only valid and accurate "
                        "information is shared across the network. The 'opnum' for this function is the unique "
                        "identifier that tells the system to perform this specific check.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            23: {
                "Method": "IDL_DRSGetObjectExistence",
                "Note": "Helps the client check the consistency of object existence between its replica of an NC "
                        "and the server's replica of the same NC. Checking the consistency of object existence "
                        "means identifying objects that have replicated to both replicas and that exist in one "
                        "replica but not in the other. For the purposes of this method, an object exists within a "
                        "NC replica if it is either an object or a tombstone."
                        ""
                        "Think of Active Directory as a city's information center where all the details about "
                        "its citizens and their roles are stored. This function is like a roll call tool. It helps "
                        "the information center check if they have all the expected records. If some citizens were "
                        "supposed to send in their details and the center isn't sure if they've received them all, "
                        "this tool would help confirm whether anything is missing or if there are any extra, "
                        "unexpected records.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            25: {
                "Method": "IDL_DRSInitDemotion",
                "Note": "Performs the first phase of the removal of a DC from an AD LDS forest. This method is "
                        "supported only by AD LDS. "
                        ""
                        "This is like starting a retirement process for a manager. It prepares the domain controller "
                        "to be demoted by making sure all the initial conditions are met and everything is in place "
                        "for a smooth transition.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            26: {
                "Method": "IDL_DRSReplicaDemotion",
                "Note": "Replicates off all changes to the specified NC and moves any FSMOs held to another server. "
                        ""
                        "This function is like handing over the responsibilities and data that the manager had to "
                        "other managers. It ensures that all the important information this domain controller has "
                        "is replicated or transferred to other domain controllers before it is demoted.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            27: {
                "Method": "IDL_DRSFinishDemotion",
                "Note": "Either performs one or more steps toward the complete removal of a DC from an AD LDS forest,"
                        " or it undoes the effects of the first phase of removal (performed by IDL_DRSInitDemotion)."
                        " This method is supported by AD LDS only. This is the final step in the retirement process. "
                        "After all the data and duties have been handed off, this function completes the demotion, "
                        "essentially removing the manager's status and ensuring the office can run smoothly without "
                        "them.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            28: {
                "Method": "IDL_DRSAddCloneDC",
                "Note": "Used to create a new DC object by copying attributes from an existing DC object. "
                        ""
                        "This function is like a cloning tool. Imagine you have a security guard (a domain controller) "
                        "that has a set of keys (security information) to many different doors in a building "
                        "(the network). If you want to create an exact copy of that guard with the same keys, so "
                        "he can help with the workload or replace the original guard if he's unavailable, you would "
                        "use this tool. It's used to make an exact replica of a domain controller, which can be "
                        "helpful for balancing the load of network traffic or for setting up a new controller "
                        "without having to configure everything from scratch.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            29: {
                "Method": "IDL_DRSWriteNgcKey",
                "Note": "Composes and updates the msDS-KeyCredentialLink value on an object. "
                        ""
                        "This function is like a key maker. It allows you to create or replace a specific type of "
                        "key (known as a Next Generation Credentials key, which is used for modern authentication "
                        "methods) for a user's account. This could be used if you need to update or reset the way "
                        "a user logs into the network to ensure their credentials are up-to-date and secure.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
            },
            30: {
                "Method": "IDL_DRSReadNgcKey",
                "Note": "Reads and parses the msDS-KeyCredentialLink value on an object. "
                        ""
                        "This function is like a specific request to the HR department for the key code to the "
                        "company's secure Wi-Fi network that only certain smartphones (specifically those belonging "
                        "to executives) can access. The 'opnum' is like a specific form number that you'd have to "
                        "fill out to get this information. In technical terms, this function reads the data related "
                        "to Next Generation Credentials (NGC), which are a type of more secure digital keys used for "
                        "authentication.",
                "ATT&CK TTP": "",
                "Attack Type": "",
                "Detects": "",
                "Detection ID": ""
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
                "Note": "This method can be used by APT groups to enumerate privileged accounts for subsequent "
                        "attacks. "
                        ""
                        "This method is invoked to request a list of account objects in the server's database. The "
                        "method can be called multiple times to return its output in fragments. "
                        ""
                        "This function is like asking the security office of a company to give you a list of all the "
                        "employee badges. It's a way to get an overview of all the user accounts that the security "
                        "system is keeping track of. You might do this to see who has access to the building, for "
                        "example.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery of Privileged Accounts"
            },
            13: {
                "Method": "LsarEnumerateTrustedDomains",
                "Note": "Understanding trust relationships is crucial for movement between domains or for Golden "
                        "Ticket attacks. "
                        ""
                        "Tis invoked to request a list of trusted domain objects in the server's database. The method "
                        "can be called multiple times to return its output in fragments. This function used to get a "
                        "list of all the trusted domains that a server knows about."
                        ""
                        "A domain is like a neighborhood, and a trusted domain is a neighborhood that's considered "
                        "friendly and safe. So, if you wanted to know which neighborhoods your local community "
                        "center trusts for its members to visit, this function would provide you with that information",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Lateral Movement Preparation"
            },
            14: {
                "Method": "LsarLookupNames",
                "Note": "The LsarLookupNames method translates a batch of security principal names to their SID "
                        "form. It also returns the domains that these names are a part of. Mapping usernames to SIDs "
                        "is useful for identifying potential targets for token impersonation attacks. This does the "
                        "opposite of LsarLookupSids. It takes a list of user account or group names and finds out "
                        "their corresponding SIDs. "
                        ""
                        "It's like asking a receptionist to find the office and job title for a person just by their "
                        "name. This function takes a list of user names and figures out their respective job titles "
                        "(in technical terms, their security identifiers or SIDs).",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Privilege Escalation and Reconnaissance"
            },
            15: {
                "Method": "LsarLookupSids",
                "Note": "The LsarLookupSids method translates a batch of security principal SIDs to their name "
                        "forms. It also returns the domains that these names are a part of. Translating SIDs "
                        "could be part of SID-History injection for assuming high-privileged account identities. "
                        ""
                        "This function takes a list of SIDs (Security Identifiers), which are unique codes that "
                        "identify user accounts or groups within a computer network, and finds out the names of "
                        "those user accounts or groups. It's like looking up a list of customer numbers to find "
                        "the actual names of the customers.",
                "ATT&CK TTP": "T1178 - SID-History Injection",
                "Attack Type": "Privilege Escalation"
            },
            23: {
                "Method": "LsarGetSystemAccessAccount",
                "Note": "The LsarGetSystemAccessAccount method is invoked to retrieve system access account flags "
                        "for an account object. System access flags can reveal the access level of accounts, "
                        "highlighting those with weak security. "
                        ""
                        "This function is used to retrieve specific settings (referred to as 'system access account "
                        "flags') that determine what a user account is permitted to do on the network. It's like "
                        "checking what services a customer has signed up for based on their account information.",
                "ATT&CK TTP": "T1003 - Credential Dumping",
                "Attack Type": "Discovery of Account Vulnerabilities"
            },
            26: {
                "Method": "LsarQueryInfoTrustedDomain",
                "Note": "Querying trusted domain info is vital for lateral movement across trust boundaries in "
                        "AD environments. "
                        ""
                        "This function is invoked to retrieve information about the trusted domain object. "
                        ""
                        "This function is like going into the records of a 'trusted' department in a company and "
                        "pulling out specific files to learn more about it. It could be details about their policies, "
                        "the way they operate, or the agreements they have with your own department.",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Lateral Movement"
            },
            35: {
                "Method": "LsarEnumerateAccountsWithUserRight",
                "Note": "Identifying accounts with specific user rights can help target accounts ideal for "
                        "exploitation. "
                        ""
                        "Invoked to return a list of account objects that have the user right equal "
                        "to the passed-in value. This method lets you list all the accounts that have a "
                        "specific right or permission in the system. For example, if you want to see a list "
                        "of all the people in a company who have the key to the storage room, this function "
                        "would give you that list.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
            },
            44: {
                "Method": "LsarOpenPolicy2",
                "Note": "Accessing policy objects can be a step towards privilege elevation or policy settings "
                        "modifications. This method opens a context handle to the RPC server. This is the first "
                        "function that MUST be called to contact the Local Security Authority (Domain Policy) "
                        "Remote Protocol database. "
                        ""
                        "This is like asking for permission to look at or change the company's security policies. "
                        "Before you can make any changes or even just view the policies, you need to get the keys to "
                        "the policy file cabinet. This function gets you those keys if you're authorized.",
                "ATT&CK TTP": "T1484 - Domain Policy Modification",
                "Attack Type": "Privilege Escalation or Policy Manipulation"
            },
            45: {
                "Method": "LsarGetUserName",
                "Note": "Returns the name and the domain name of the security principal that is invoking the method. "
                        "This is like asking, 'Who am I?' to the receptionist. It’s a simple request that tells you "
                        "your own name and job title as per the office records.",
                "ATT&CK TTP": "",
                "Attack Type": ""
            },
            76: {
                "Method": "lsa_LookupSids3",
                "Note": "Resolving SIDs to account names can map out users and groups for further attacks within "
                        "AD environments. "
                        ""
                        "The LsarLookupSids3 method translates a batch of security principal SIDs to their name forms. "
                        "It also returns the domains that these names are a part of. "
                        ""
                        "Imagine every worker has a unique ID badge. This function takes a bunch of these ID "
                        "numbers and matches them to the worker's names and their departments. It's like a reverse "
                        "phonebook for employee IDs that helps figure out who these IDs belong to.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Reconnaissance"
            },
            77: {
                "Method": "lsa_LookupNames4",
                "Note": "Translating account names to SIDs can aid in creating Golden Tickets and identifying "
                        "targets for escalation. "
                        ""
                        "The LsarLookupNames4 method translates a batch of security principal names to their SID "
                        "form. It also returns the domains of which these security principals are a part. This one "
                        "is the opposite of lsa_LookupSids3. Instead of starting with ID badges, you start with "
                        "names and this function finds their corresponding ID numbers. It's like looking up the "
                        "serial number of a product by its name to find out more information about it."
                        ""
                        "This function is a newer, more efficient way of doing what LsarLookupNames does. It's "
                        "like having an upgraded office directory that not only tells you the job titles but also "
                        "other details like the department and direct line for each employee.",
                "ATT&CK TTP": "T1558.001 - Golden Ticket",
                "Attack Type": "Credential Theft and Privilege Escalation"
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
                "Note": "This function is involved in processing user logon requests and is susceptible to brute "
                        "force attacks if weak passwords are used. This is like the security guard checking an "
                        "employee's ID card when they arrive at work. It's a way for the computer to check with "
                        "the network's security system to make sure a user is who they say they are when they try "
                        "to log in."
                        ""
                        "The NetrLogonSamLogon method is a predecessor to the NetrLogonSamLogonWithFlags method "
                        "(section 3.5.4.5.2). All parameters of this method have the same meanings as the "
                        "identically named parameters of the NetrLogonSamLogonWithFlags method.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
            },
            3: {
                "Method": "NetrLogonSamLogoff",
                "Note": "This method manages user logoff requests and can disrupt sessions, potentially being used "
                        "for denial-of-service attacks. This is like the security guard logging the time when an "
                        "employee leaves. It tells the network's security system that the user is done working and "
                        "logs them out, helping to keep the user's account secure when they're not using it. "
                        ""
                        "The NetrLogonSamLogoff method SHOULD update the user lastLogoff attribute for the SAM "
                        "accounts.",
                "ATT&CK TTP": "T1485 - Data Destruction",
                "Attack Type": "Denial of Service"
            },
            4: {
                "Method": "NetrServerReqChallenge",
                "Note": "Part of the secure channel establishment process, this method is used in the initial stages "
                        "of the Zerologon exploit. Imagine this as the security guard asking for a password before "
                        "letting someone in. It's a part of the process where the computer and the network's security"
                        " system agree on a 'secret handshake' so that they can communicate securely. "
                        ""
                        "The NetrServerReqChallenge method SHOULD receive a client challenge and return a server "
                        "challenge (SC).",
                "ATT&CK TTP": "T1075 - Pass the Hash",
                "Attack Type": "Credential Access via Zerologon"
            },
            31: {
                "Method": "NetrServerPasswordGet",
                "Note": "This method can be exploited to retrieve machine account passwords, aiding in lateral "
                        "movement or privilege escalation. This is like a manager asking the guard for the keys to "
                        "a locked office. It's a function that allows a server to retrieve the stored password or "
                        "a related secret for a computer or user, which is necessary for verifying identity and "
                        "maintaining security."
                        ""
                        "The NetrServerPasswordGet method SHOULD allow a BDC to get a machine account password "
                        "from the DC with the PDC role in the domain.",
                "ATT&CK TTP": "T1003 - Credential Dumping",
                "Attack Type": "Lateral Movement"
            },
            7: {
                "Method": "NetrDatabaseDeltas",
                "Note": "Used in domain replication, this method can be co-opted by attackers to intercept "
                        "sensitive replication data. This function is like a security guard checking what has "
                        "changed in the personnel files since the last check. It lists the recent changes made "
                        "to user accounts or security policies within the network."
                        ""
                        "The NetrDatabaseDeltas method SHOULD return a set of changes (or deltas) performed to "
                        "the SAM database, SAM built-in database, or LSA databases after a particular value of "
                        "the database serial number. It is used by BDCs to request database changes from the PDC "
                        "that are missing on the BDC.",
                "ATT&CK TTP": "T1107 - File Deletion",
                "Attack Type": "Defense Evasion by Deleting Evidence"
            },
            26: {
                "Method": "NetrServerAuthenticate3",
                "Note": "Central to the Zerologon attack, this method can be used to bypass authentication controls "
                        "by changing the machine password. Imagine a security checkpoint where guards verify the "
                        "identity of a person before letting them into a secure area. This function is the computer "
                        "equivalent, where a server checks to make sure another server or computer is who it claims "
                        "to be before allowing access to secure resources. "
                        ""
                        "The NetrServerAuthenticate3 method SHOULD mutually authenticate the client and the server "
                        "and establish the session key to be used for the secure channel message protection between "
                        "the client and the server. It is called after the NetrServerReqChallenge method",
                "ATT&CK TTP": "T1557 - Man-in-the-Middle",
                "Attack Type": "Credential Access and Defense Evasion"
            },
            42: {
                "Method": "NetrServerTrustPasswordsGet",
                "Note": "This method can be abused to retrieve inter-domain trust passwords, potentially compromising"
                        " the entire AD forest. This could be likened to a higher-up security officer who has the "
                        "authority to access the master keys or passwords for various doors in the building. The "
                        "function retrieves special passwords (trust passwords) that are used by domain controllers "
                        "to establish secure communication with each other."
                        ""
                        "The NetrServerTrustPasswordsGet method SHOULD return the encrypted current and previous "
                        "passwords for an account in the domain. This method is called by a client to retrieve "
                        "the current and previous account passwords from a domain controller. The account name "
                        "requested MUST be the name used when the secure channel was created, unless the method "
                        "is called on a PDC by a DC, in which case it can be any valid account name.",
                "ATT&CK TTP": "T1482 - Domain Trust Discovery",
                "Attack Type": "Discovery and Lateral Movement"
            },
            29: {
                "Method": "NetrLogonGetDomainInfo",
                "Note": "Can be used for extensive domain reconnaissance, potentially aiding in credential-based "
                        "attacks like pass-the-hash. "
                        ""
                        "The NetrLogonGetDomainInfo method SHOULD return information that describes the current "
                        "domain to which the specified client belongs.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery and Credential Access"
            },
            30: {
                "Method": "NetrServerPasswordSet2",
                "Note": "This method is abused post-exploitation to alter machine account passwords, taking over "
                        "the machine's domain identity. "
                        ""
                        "The NetrServerPasswordSet2 method SHOULD allow the client to set a new clear text password "
                        "for an account used by the domain controller for setting up the secure channel from the "
                        "client. A domain member SHOULD use this function to periodically change its machine account "
                        "password. A PDC uses this function to periodically change the trust password for all "
                        "directly trusted domains.",
                "ATT&CK TTP": "T1098 - Account Manipulation",
                "Attack Type": "Persistence and Privilege Escalation"
            },
            34: {
                "Method": "DsrGetDcNameEx2",
                "Note": "Often used for gathering information about domain controllers, this method can be a "
                        "precursor to a DCSync attack. "
                        ""
                        "The DsrGetDcNameEx2 method SHOULD return information about a domain controller (DC) in the "
                        "specified domain and site. If the AccountName parameter is not NULL, and a DC matching the "
                        "requested capabilities (as defined in the Flags parameter) responds during this method call, "
                        "then that DC will have verified that the DC account database contains an account for the "
                        "AccountName specified. The server that receives this call is not required to be a DC.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery for DCSync Attack"
            },
            40: {
                "Method": "DsrEnumerateDomainTrusts",
                "Note": "The DsrEnumerateDomainTrusts method SHOULD return an enumerated list of domain trusts, "
                        "filtered by a set of flags, from the specified server.",
                "ATT&CK TTP": "",
                "Attack Type": ""
            },
            46: {
                "Method": "NetrServerGetTrustInfo",
                "Note": "This method can be misused to forge inter-realm trust tickets, commonly known as Silver "
                        "Ticket attacks. "
                        ""
                        "The NetrServerGetTrustInfo method SHOULD return an information block from a specified "
                        "server. The information includes encrypted current and previous passwords for a particular "
                        "account and additional trust data. The account name requested MUST be the name used when "
                        "the secure channel was created, unless the method is called on a PDC by a domain controller, "
                        "in which case it can be any valid account name.",
                "ATT&CK TTP": "T1558.002 - Silver Ticket",
                "Attack Type": "Credential Access and Persistence"
            },
            45: {
                "Method": "NetrLogonSamLogonWithFlags",
                "Note": "This extended logon method may be vulnerable to similar attacks as NetrLogonSamLogon, "
                        "with added flag manipulation risks. "
                        ""
                        "The NetrLogonSamLogonWithFlags method SHOULD handle "
                        "logon requests for the SAM accounts.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
            },
            39: {
                "Method": "NetrLogonSamLogonEx",
                "Note": "This enhanced logon function could be exploited for unauthorized access, potentially "
                        "enabling more sophisticated attacks. "
                        ""
                        "The NetrLogonSamLogonEx method SHOULD provide an "
                        "extension to NetrLogonSamLogon that accepts an extra flags parameter and uses Secure "
                        "RPC ([MS-RPCE] section 3.3.1.5.2) instead of Netlogon authenticators. This method handles"
                        " logon requests for the SAM accounts and allows for generic pass-through authentication.",
                "ATT&CK TTP": "T1110 - Brute Force",
                "Attack Type": "Credential Access via Password Spraying"
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
                "Note": "Can be used by attackers to map out Active Directory domains within an organization, "
                        "understanding its structure for further attacks."
                        ""
                        "The SamrEnumerateDomainsInSamServer method obtains a listing of all domains hosted by the "
                        "server side of this protocol. It's like asking for a complete list of all the departments in "
                        "a large company. ",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery"
            },
            5: {
                "Method": "SamrLookupDomainInSamServer",
                "Note": "May be used to resolve domain names to SIDs, aiding in lateral movement and privilege "
                        "escalation strategies by attackers."
                        ""
                        "Used to find the unique identifier (known as the Security Identifier, or SID) for a "
                        "specific domain based on the domain's name. This is akin to looking up a specific "
                        "department's internal code by its name.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
            },
            17: {
                "Method": "SamrLookupNamesInDomain",
                "Note": "Translating usernames to RIDs can help in account compromise by linking usernames to "
                        "specific domain accounts."
                        ""
                        "Translates a set of account names into a set of RIDs.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Credential Access"
            },
            13: {
                "Method": "SamrEnumerateUsersInDomain",
                "Note": "Used to enumerate user accounts, which can be exploited by threat actors to identify "
                        "targets for credential theft."
                        ""
                        "Enumerates all users.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Credential Access"
            },
            7: {
                "Method": "SamrOpenDomain",
                "Note": "Allows establishing a session with a domain object, potentially for reconnaissance or "
                        "domain object modifications."
                        ""
                        "Obtains a handle to a domain object, given a SID.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Discovery"
            },
            8: {
                "Method": "SamrQueryInformationDomain",
                "Note": "Could be used to extract domain policies, informing attackers on how to tailor their "
                        "attacks, like password spraying."
                        ""
                        "Obtains attributes from a domain object.",
                "ATT&CK TTP": "T1201 - Password Policy Discovery",
                "Attack Type": "Credential Access"
            },
            34: {
                "Method": "SamrOpenUser",
                "Note": "Opening user objects can allow attackers to gather detailed information or modify "
                        "attributes for persistence or privilege escalation."
                        ""
                        "Obtains a handle to a user, given a RID.",
                "ATT&CK TTP": "T1087 - Account Discovery",
                "Attack Type": "Persistence"
            },
            36: {
                "Method": "SamrQueryInformationUser",
                "Note": "Querying for user information such as last logon times can be used for targeting active "
                        "users in phishing or other campaigns."
                        ""
                        "Obtains attributes from a user object.",
                "ATT&CK TTP": "T1078 - Valid Accounts",
                "Attack Type": "Credential Access"
            },
            25: {
                "Method": "SamrGetMembersInGroup",
                "Note": "Identifying group memberships, particularly administrative ones, can aid attackers in "
                        "targeting privileged accounts for attacks."
                        ""
                        "Reads the members of a group.",
                "ATT&CK TTP": "T1069 - Permission Groups Discovery",
                "Attack Type": "Privilege Escalation"
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
                "Note": "Can be used by APT groups to enumerate network shares for lateral movement and data "
                        "harvesting."
                        ""
                        "Retrieves a list of all shared resources on a server. Think of it as asking the server for "
                        "a complete catalog of everything it's currently sharing with others. This could include "
                        "shared folders, printers, and other resources that are available on the network for use by "
                        "authorized individuals."
                        ""
                        "The NetrShareEnum method retrieves information about each shared resource on a server.",
                "ATT&CK TTP": "T1135 - Network Share Discovery",
                "Attack Type": "Discovery and Lateral Movement"
            },
            16: {
                "Method": "NetrShareGetInfo",
                "Note": "May be used by adversaries to gather detailed information about specific network shares."
                        ""
                        "More specific than NetrShareEnum. Gets detailed information about a particular shared "
                        "resource from the server. It's like looking up detailed information about one item in "
                        "the catalog, such as who can access a specific shared folder and what permissions they have."
                        ""
                        "Retrieves information about a particular shared resource on the server from the ShareList.",
                "ATT&CK TTP": "T1082 - System Information Discovery",
                "Attack Type": "Discovery"
            },
            12: {
                "Method": "NetrSessionEnum",
                "Note": "Could be leveraged by attackers to gather information on active user sessions for targeted "
                        "attacks or scope access."
                        ""
                        "Provides information about sessions that are established on a server. A session is created "
                        "when a user or a computer connects to another computer on the network to access shared "
                        "resources. This function could be used to get a list of all such connections, which includes "
                        "details about the users who are connected and the computers they're connecting from."
                        ""
                        "The NetrSessionEnum method MUST return information about sessions that are established on a "
                        "server or return an error code.",
                "ATT&CK TTP": "T1049 - System Network Connections Discovery",
                "Attack Type": "Discovery"
            },
            13: {
                "Method": "NetrSessionDel",
                "Note": "Might be used by threat actors to remove sessions and cover tracks after data exfiltration."
                        ""
                        "The NetrSessionDel method MUST end one or more network sessions between a server and a "
                        "client.",
                "ATT&CK TTP": "T1070 - Indicator Removal on Host",
                "Attack Type": "Defense Evasion"
            },
            9: {
                "Method": "NetrFileEnum",
                "Note": "Can be abused to monitor file usage patterns and identify critical assets for attack planning."
                        ""
                        "The NetrFileEnum method MUST return information about some or all open files on a server, "
                        "depending on the parameters specified, or return an error code.",
                "ATT&CK TTP": "T1083 - File and Directory Discovery",
                "Attack Type": "Discovery"
            },
            11: {
                "Method": "NetrFileClose",
                "Note": "If abused, this could be used to interfere with critical processes or alter files, "
                        "potentially in ransomware attacks."
                        ""
                        "The server receives the NetrFileClose method in an RPC_REQUEST packet. In response, the "
                        "server MUST force an open resource instance (for example, file, device, or named pipe) on "
                        "the server to close. This message can be used when an error prevents closure by any other "
                        "means.",
                "ATT&CK TTP": "T1489 - Service Stop",
                "Attack Type": "Impact"
            },
            14: {
                "Method": "NetrShareAdd",
                "Note": "Exploitable by APTs to create network shares for data exfiltration or persistent access."
                        ""
                        "The NetrShareAdd method shares a server resource.",
                "ATT&CK TTP": "T1135 - Network Share Discovery",
                "Attack Type": "Persistence and Lateral Movement"
            },
            18: {
                "Method": "NetrShareDel",
                "Note": "Could be used post-compromise to remove evidence of unauthorized network shares."
                        ""
                        "The NetrShareDel method deletes a share name from the ShareList, which disconnects all "
                        "connections to the shared resource. If the share is sticky, all information about the share "
                        "is also deleted from permanent storage.",
                "ATT&CK TTP": "T1070 - Indicator Removal on Host",
                "Attack Type": "Defense Evasion"
            },
            17: {
                "Method": "NetrShareSetInfo",
                "Note": "May be exploited to change share permissions, allowing unauthorized data access."
                        ""
                        "The NetrShareSetInfo method sets the parameters of a shared resource in a ShareList.",
                "ATT&CK TTP": "T1222 - File and Directory Permissions Modification",
                "Attack Type": "Privilege Escalation"
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
    },
    "references": {
        "url1": "https://github.com/jsecurity101/MSRPC-to-ATTACK/tree/main",
        "samr": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/e8205d2c-9ebb-4845-b927-0aca7cbc1f2c",
        "drsuapi": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410",
        "lsarpc": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/86f5e73b-98c4-4234-89cb-d9ff5f327b73"
    }
}
