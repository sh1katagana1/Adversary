# Summary
Scattered Spider is a cybercriminal group that targets large companies and their contracted information technology (IT) help desks. Scattered Spider threat actors, per trusted third parties, have typically engaged in data theft for extortion and have also been known to utilize BlackCat/ALPHV ransomware alongside their usual TTPs.

# Aliases
Starfraud 
UNC3944 
Scatter Swine
Muddled Libra

# Known legitimate tools Scattered Spider utilizes
1. Fleetdeck.io-Enables remote monitoring and management of systems.
2. Level.io-Enables remote monitoring and management of systems.
3. Mimikatz-Extracts credentials from a system.
4. Ngrok-Enables remote access to a local web server by tunneling over the internet.
5. Pulseway-Enables remote monitoring and management of systems.
6. Screenconnect-Enables remote connections to network devices for management.
7. Splashtop-Enables remote connections to network devices for management.
8. Tactical.RMM-Enables remote monitoring and management of systems.
9. Tailscale-Provides virtual private networks (VPNs) to secure network communications.
10. Teamviewer-Enables remote connections to network devices for management.

# Malware used by Scattered Spider
1. AveMaria (also known as WarZone)-Enables remote access to a victim’s systems.
2. Raccoon Stealer-Steals information including login credentials, browser history, cookies, and other data.
3. VIDAR Stealer-Steals information including login credentials, browser history, cookies, and other data.

# Domains used by Scattered Spider (replace victimname with the actual name of the victim)
1. victimname-sso.com
2. victimname-servicedesk.com
3. victimname-okta.com


# Typical Phishing-to-initial-access process
In most instances, Scattered Spider threat actors conduct SIM swapping attacks against users that respond to the phishing/smishing attempt. The threat actors then work to identify the personally identifiable information (PII) of the most valuable users that succumbed to the phishing/smishing, obtaining answers for those users’ security questions. After identifying usernames, passwords, PII, and conducting SIM swaps, the threat actors then use social engineering techniques to convince IT help desk personnel to reset passwords and/or MFA tokens, to perform account takeovers against the users in single sign-on (SSO) environments.

# Execution, Persistence, and Privilege Escalation
Scattered Spider threat actors then register their own MFA tokens, after compromising a user’s account to establish persistence. Further, the threat actors add a federated identity provider to the victim’s SSO tenant and activate automatic account linking. The threat actors are then able to sign into any account by using a matching SSO account attribute. At this stage, the Scattered Spider threat actors already control the identity provider and then can choose an arbitrary value for this account attribute. As a result, this activity allows the threat actors to perform privileged escalation and continue logging in even when passwords are changed. Additionally, they leverage common endpoint detection and response (EDR) tools installed on the victim networks to take advantage of the tools’ remote-shell capabilities and executing of commands which elevates their access. They also deploy remote monitoring and management (RMM) tools to then maintain persistence.

# Discovery, Lateral Movement, and Exfiltration
Once persistence is established on a target network, Scattered Spider threat actors often perform discovery, specifically searching for SharePoint sites, credential storage documentation, VMware vCenter infrastructure, backups, and instructions for setting up/logging into Virtual Private Networks (VPN). The threat actors enumerate the victim’s Active Directory (AD), perform discovery and exfiltration of victim's code repositories, code-signing certificates, and source code. Threat actors activate Amazon Web Services (AWS) Systems Manager Inventory to discover targets for lateral movement, then move to both preexisting and actor-created Amazon Elastic Compute Cloud (EC2) instances. In instances where the ultimate goal is data exfiltration, Scattered Spider threat actors use actor-installed extract, transform, and load (ETL) tools to bring data from multiple data sources into a centralized database. According to trusted third parties, where more recent incidents are concerned, Scattered Spider threat actors may have deployed BlackCat/ALPHV ransomware onto victim networks—thereby encrypting VMware Elastic Sky X integrated (ESXi) servers.

To determine if their activities have been uncovered and maintain persistence, Scattered Spider threat actors often search the victim's Slack, Microsoft Teams, and Microsoft Exchange online for emails or conversations regarding the threat actor's intrusion and any security response. The threat actors frequently join incident remediation and response calls and teleconferences, likely to identify how security teams are hunting them and proactively develop new avenues of intrusion in response to victim defenses. This is sometimes achieved by creating new identities in the environment and is often upheld with fake social media profiles to backstop newly created identities.


# Key Characteristics

1. Posed as company IT and/or helpdesk staff using phone calls or SMS messages to obtain credentials from employees and gain access to the network
2. Posed as company IT and/or helpdesk staff to direct employees to run commercial remote access tools enabling initial access
3. Posed as IT staff to convince employees to share their one-time password (OTP), an MFA authentication code.
4. Sent repeated MFA notification prompts leading to employees pressing the “Accept” button (also known as MFA fatigue)
5. Convinced cellular carriers to transfer control of a targeted user’s phone number to a SIM card they controlled, gaining control over the phone and access to MFA prompts.
6. Monetized access to victim networks in numerous ways including extortion enabled by ransomware and data theft
7. After gaining access to networks, Scattered Spider threat actors using publicly available, legitimate remote access tunneling tools. 
8. Scattered Spider threat actors have historically evaded detection on target networks by using living off the land techniques and allowlisted applications to navigate victim networks, as well as frequently modifying their TTPs.
9. Scattered Spider threat actors have exfiltrated data after gaining access and threatened to release it without deploying ransomware; this includes exfiltration to multiple sites including U.S.-based data centers and MEGA.NZ
10. After exfiltrating and/or encrypting data, Scattered Spider threat actors communicate with victims via TOR, Tox, email, or encrypted applications.
11. Scattered Spider intrusions often begin with broad phishing and smishing attempts against a target using victim-specific crafted domains
12. In most instances, Scattered Spider threat actors conduct SIM swapping attacks against users that respond to the phishing/smishing attempt.
13. They target VMWare
14. They exfil code signing certificates, likely as they would be trusted by the company


# Mitigations
1. Incorporate secure-by-design and -default principles and tactics into your software development practices limiting the impact of ransomware techniques, thus, strengthening the secure posture for their customers.
2. Implement application controls to manage and control execution of software, including allowlisting remote access programs. Application controls should prevent installation and execution of portable versions of unauthorized remote access and other software. A properly configured application allowlisting solution will block any unlisted application execution. Allowlisting is important because antivirus solutions may fail to detect the execution of malicious portable executables when the files use any combination of compression, encryption, or obfuscation. 
3. Auditing remote access tools on your network to identify currently used and/or authorized software.
4. Reviewing logs for execution of remote access software to detect abnormal use of programs running as a portable executable 
5. Using security software to detect instances of remote access software being loaded only in memory.
6. Requiring authorized remote access solutions to be used only from within your network over approved remote access solutions, such as virtual private networks (VPNs) or virtual desktop interfaces (VDIs).
7. Blocking both inbound and outbound connections on common remote access software ports and protocols at the network perimeter.
8. Follow the RMM hardening recommendations found here: https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf
9. Implementing FIDO/WebAuthn authentication or Public Key Infrastructure (PKI)-based MFA. These MFA implementations are resistant to phishing and not suspectable to push bombing or SIM swap attacks, which are techniques known to be used by Scattered Spider actors. 
10. Strictly limit the use of Remote Desktop Protocol (RDP) and other remote desktop services. If RDP is necessary, rigorously apply best practices, such as applying MFA.
11. Implement a recovery plan to maintain and retain multiple copies of sensitive or proprietary data and servers in a physically separate, segmented, and secure location (i.e., hard drive, storage device, the cloud).
12. Maintain offline backups of data and regularly maintain backup and restoration (daily or weekly at minimum). By instituting this practice, an organization limits the severity of disruption to its business practices
13. Require all accounts with password logins (e.g., service account, admin accounts, and domain admin accounts) to comply with NIST's standards for developing and managing password policies.
14. Require phishing-resistant multifactor authentication (MFA) for all services to the extent possible, particularly for webmail, virtual private networks (VPNs), and accounts that access critical systems
15. Keep all operating systems, software, and firmware up to date. Timely patching is one of the most efficient and cost-effective steps an organization can take to minimize its exposure to cybersecurity threats. Prioritize patching known exploited vulnerabilities in internet-facing systems
16. Segment networks to prevent the spread of ransomware. Network segmentation can help prevent the spread of ransomware by controlling traffic flows between—and access to—various subnetworks and by restricting adversary lateral movement 
17. Identify, detect, and investigate abnormal activity and potential traversal of the indicated ransomware with a networking monitoring tool. To aid in detecting the ransomware, implement a tool that logs and reports all network traffic and activity, including lateral movement, on a network. Endpoint detection and response (EDR) tools are particularly useful for detecting lateral connections as they have insight into common and uncommon network connections for each host
18. Install, regularly update, and enable real time detection for antivirus software on all hosts.
19. Disable unused ports and protocols
20. Consider adding an email banner to emails received from outside your organization
21. Disable hyperlinks in received emails.
22. Ensure all backup data is encrypted, immutable (i.e., ensure backup data cannot be altered or deleted), and covers the entire organization’s data infrastructure

# References
https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
https://attack.mitre.org/versions/v14/groups/G1015/
https://www.trellix.com/en-us/about/newsroom/stories/research/scattered-spider-the-modus-operandi.html
https://www.crowdstrike.com/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/
https://www.crowdstrike.com/blog/scattered-spider-attempts-to-avoid-detection-with-bring-your-own-vulnerable-driver-tactic/
https://www.malwarebytes.com/blog/personal/2023/09/ransomware-group-steps-up-issues-statement-over-mgm-resorts-compromise


# MITRE
* T1589-Gather Victim Identity Information
* T1598-Phishing for Information
T1583.001-Acquire Infrastructure: Domains
T1585.001-Establish Accounts: Social Media Accounts
T1566-Phishing
T1660-Phishing (Mobile)
T1566.004-Phishing: Spearphishing Voice
T1199-Trusted Relationship
T1078.002-Valid Accounts: Domain Accounts
T1648-Serverless Execution
T1204-User Execution
T1136-Create Account
T1556.006-Modify Authentication Process: Multi-Factor Authentication
T1078-Valid Accounts
T1484.002-Domain Policy Modification: Domain Trust Modification
T1578.002-Modify Cloud Compute Infrastructure: Create Cloud Instance
T1606-Forge Web Credentials
T1621-Multi-Factor Authentication Request Generation
T1552.001-Unsecured Credentials: Credentials in Files
T1552.004-Unsecured Credentials: Private Keys
T1217-Browser Information Discovery
T1538-Cloud Service Dashboard
T1083-File and Directory Discovery
T1018-Remote System Discovery
T1539-Steal Web Session Cookie
T1021.007-Remote Services: Cloud Services
T1213.003-Data from Information Repositories: Code Repositories
T1213.002-Data from Information Repositories: Sharepoint
T1074-Data Staged
T1114-Email Collection
T1530-Data from Cloud Storage
T1219-Remote Access Software
T1486-Data Encrypted for Impact
T1567.002-Exfiltration Over Web Service: Exfiltration to Cloud Storage
T1657-Financial Theft


# IOCs
0440ef40c46fdd2b5d86e7feef8577a8591de862cfd7928cdbcc8f47b8fa3ffc
9b1b15a3aacb0e786a608726c3abfc94968915cedcbd239ddf903c4a54bfcf0c
c8f9e1ad7b8cce62fba349a00bc168c849d42cfb2ca5b2c6cc4b51d054e0c497
5f6fec8f7890d032461b127332759c88a1b7360aa10c6bd38482572f59d2ba8b
6839fcae985774427c65fe38e773aa96ec451a412caa5354ad9e2b9b54ffe6c1
7f4555a940ce1156c9bcea9a2a0b801f9a5e44ec9400b61b14a7b1a6404ffdf6
d7c81b0f3c14844f6424e8bdd31a128e773cb96cccef6d05cbff473f0ccb9f9c
8e035beb02a411f8a9e92d4cf184ad34f52bbd0a81a50c222cdd4706e4e45104
648c2067ef3d59eb94b54c43e798707b030e0383b3651bcc6840dae41808d3a9
0d10c4b2f56364b475b60bd2933273c8b1ed2176353e59e65f968c61e93b7d99
274340f7185a0cc047d82ecfb2cce5bd18764ee558b5227894565c2f9fe9f6ab
42b22faa489b5de936db33f12184f6233198bdf851a18264d31210207827ba25
982dda5eec52dd54ff6b0b04fd9ba8f4c566534b78f6a46dada624af0316044e
b6e82a4e6d8b715588bf4252f896e40b766ef981d941d0968f29a3a444f68fef
e23283e75ed2bdabf6c703236f5518b4ca37d32f78d3d65b073496c12c643cfe
acadf15ec363fe3cc373091cbe879e64f935139363a8e8df18fd9e59317cc918
3ea2d190879c8933363b222c686009b81ba8af9eb6ae3696d2f420e187467f08
4188736108d2b73b57f63c0b327fb5119f82e94ff2d6cd51e9ad92093023ec93
443dc750c35afc136bfea6db9b5ccbdb6adb63d3585533c0cf55271eddf29f58
4f94155e5a1a30f7b05280dd5d62c3410bcc52aea03271d086afa5dc5d97e585





