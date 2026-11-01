# Detection Rules

> Generated from the rule classes in `backend/app/detection/rules/` (`python -m scripts.generate_rules_doc`).
> The code is the source of truth. Every rule can also be exported as Sigma YAML from the Detection Rules page
> or `GET /api/rules/{id}/sigma`.

Rules are pure functions of (events, parameters, inventory, threat-intel feed): no I/O and no global state. Each one
has unit tests in `backend/tests/` and an end-to-end validation in `backend/tests/test_scenarios.py`.

| ID | Rule | Type | Default severity | MITRE ATT&CK | Validated by scenario |
|---|---|---|---|---|---|
| LAB-001 | SSH Brute Force | threshold | high | T1110.001 | `ssh-bruteforce-compromise` |
| LAB-002 | Windows Account Brute Force | threshold | medium | T1110.001 | `windows-password-spray`, `forgotten-password` |
| LAB-003 | Password Spraying | threshold | high | T1110.003 | `windows-password-spray` |
| LAB-004 | Successful Login After Brute Force | correlation | critical | T1110, T1078 | `ssh-bruteforce-compromise`, `windows-password-spray` |
| LAB-005 | Privileged Logon Outside Business Hours | behavioral | medium | T1078 | `after-hours-maintenance` |
| LAB-006 | Direct Root SSH Login | single_event | high | T1078.003 | `linux-backdoor-account` |
| LAB-007 | New Account Created | single_event | medium | T1136.001 | `rogue-admin-persistence`, `linux-backdoor-account` |
| LAB-008 | User Added to Privileged Group | correlation | high | T1098 | `rogue-admin-persistence`, `linux-backdoor-account` |
| LAB-009 | Suspicious PowerShell Execution | behavioral | high | T1059.001 | `powershell-download-cradle` |
| LAB-010 | Security Audit Log Cleared | single_event | critical | T1070.001 | `powershell-download-cradle` |
| LAB-011 | Scheduled Task Created | single_event | medium | T1053.005 | `rogue-admin-persistence` |
| LAB-012 | New Service Installed | single_event | medium | T1543.003 | `lateral-movement-service` |
| LAB-013 | Lateral Movement: Logons to Multiple Hosts | threshold | high | T1021.002, T1021.001 | `lateral-movement-service` |
| LAB-014 | Sudo Privilege Escalation Attempt | threshold | medium | T1548.003 | `ssh-bruteforce-compromise` |
| LAB-015 | LSASS Memory Access | behavioral | critical | T1003.001 | `lsass-credential-dumping` |
| LAB-016 | Threat Intelligence Indicator Match | enrichment | high | T1071 | `powershell-download-cradle`, `lsass-credential-dumping` |
| LAB-017 | Office Application Spawned a Shell | single_event | high | T1204.002 | `powershell-download-cradle` |
| LAB-018 | Account Takeover Followed by PIX Transfer | correlation | high | T1078, T1098, T1657 | `pix-account-takeover`, `pix-new-phone-verified` |

## LAB-001 - SSH Brute Force

High volume of failed SSH authentications from a single source against one host.

- **Type:** threshold  
- **Data sources:** linux_auth  
- **Severity:** high  
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing (Credential Access)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Failed attempts (`threshold`) | 8 | 3-100 |
| Time window (`window_minutes`) | 5 min | 1-60 |

**Logic**

```text
event_source = linux_auth AND event_action = logon_failed
| group by source_ip, hostname
| alert when count >= 8 within 5 min
```

**Known false positives**

- Automation or monitoring with an expired key/password retrying in a loop.
- Internal vulnerability scanners performing authenticated checks.

**Response**

1. Check whether any login from the same source succeeded (see LAB-004).
2. Block the source IP at the perimeter firewall / fail2ban.
3. Disable password authentication on internet-facing SSH; require keys + MFA.
4. Review targeted accounts for weak or default passwords.

## LAB-002 - Windows Account Brute Force

Repeated failed Windows logons (4625) for the same account in a short period.

- **Type:** threshold  
- **Data sources:** windows_security  
- **Severity:** medium  
- **ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing (Credential Access)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Failed attempts (`threshold`) | 6 | 3-100 |
| Time window (`window_minutes`) | 5 min | 1-60 |

**Logic**

```text
event_id = 4625
| group by username
| alert when count >= 6 within 5 min
| severity = high if account is privileged
```

**Known false positives**

- User with a stale password cached on a phone or mapped drive after a password change.
- Service configured with an old password after rotation.

**Response**

1. Contact the account owner to confirm whether they were typing the password.
2. Check for account lockout (4740) and the calling workstation.
3. If unexpected, reset the password and review sign-ins after the burst.

## LAB-003 - Password Spraying

One source fails authentication against many different accounts, with few attempts per account.

- **Type:** threshold  
- **Data sources:** windows_security, linux_auth  
- **Severity:** high  
- **ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying (Credential Access)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Distinct accounts (`distinct_users`) | 5 | 3-100 |
| Time window (`window_minutes`) | 15 min | 1-120 |
| Max attempts per account (`max_attempts_per_user`) | 3 | 1-20 |

**Logic**

```text
event_action = logon_failed
| group by source_ip
| alert when distinct(username) >= 5 within 15 min
|   AND avg attempts per account <= 3
```

**Known false positives**

- Shared kiosk or VDI gateway where many users mistype passwords (source is the gateway).
- Identity provider or proxy that forwards authentications from a single IP.

**Response**

1. Identify any account that later authenticated successfully from the same source.
2. Force password reset for successful targets and enforce MFA.
3. Block the source and hunt for the same pattern from adjacent IPs.

## LAB-004 - Successful Login After Brute Force

A source that generated many failed logons subsequently authenticated successfully.

- **Type:** correlation  
- **Data sources:** windows_security, linux_auth  
- **Severity:** critical  
- **ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force (Credential Access); [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts (Initial Access)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Prior failures (`min_failures`) | 5 | 2-100 |
| Lookback (`lookback_minutes`) | 30 min | 5-240 |

**Logic**

```text
event_action = logon_success AS s
| join event_action = logon_failed AS f ON f.source_ip = s.source_ip
|   WHERE f.timestamp in [s.timestamp - 30 min, s.timestamp]
| alert when count(f) >= 5
```

**Known false positives**

- User who forgot the password and eventually typed it correctly from a shared NAT address.

**Response**

1. Treat the account as compromised: disable or reset credentials and revoke sessions/keys.
2. Isolate the destination host and collect volatile evidence.
3. Review everything the account did after the successful login (process, sudo, account changes).

## LAB-005 - Privileged Logon Outside Business Hours

Interactive logon by a privileged account outside business hours or on a weekend.

- **Type:** behavioral  
- **Data sources:** windows_security, linux_auth  
- **Severity:** medium  
- **ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts (Initial Access)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Business hours start (`business_start`) | 7 h | 0-23 |
| Business hours end (`business_end`) | 20 h | 1-24 |

**Logic**

```text
event_action = logon_success AND identity.privileged = true AND identity.type in (human, admin)
| where logon_type in (2, 10, 11) OR event_source = linux_auth
| where local_time.hour not in [7, 20) OR weekend
```

**Known false positives**

- Planned maintenance or patching windows (check the change calendar).
- On-call administrators responding to an outage.

**Response**

1. Check the change calendar and on-call schedule.
2. Contact the administrator through an out-of-band channel to confirm.
3. If unconfirmed, review the session activity and reset the credential.

## LAB-006 - Direct Root SSH Login

Successful SSH authentication directly as root, bypassing individual accountability.

- **Type:** single_event  
- **Data sources:** linux_auth  
- **Severity:** high  
- **ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003/) Valid Accounts: Local Accounts (Privilege Escalation)

**Logic**

```text
event_source = linux_auth AND event_action = logon_success AND username = root
```

**Known false positives**

- Break-glass access during an incident when named accounts are unavailable.

**Response**

1. Confirm whether a break-glass procedure was invoked.
2. Set PermitRootLogin no and require named accounts + sudo.
3. If unexpected, rotate root credentials/keys and review commands executed.

## LAB-007 - New Account Created

A new local or domain user account was created.

- **Type:** single_event  
- **Data sources:** windows_security, linux_auth  
- **Severity:** medium  
- **ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account (Persistence)

**Logic**

```text
event_action = user_created   (Windows 4720, Linux useradd)
```

**Known false positives**

- Regular onboarding performed by the IT team (match against HR/onboarding tickets).

**Response**

1. Find the onboarding or change ticket that justifies the account.
2. Check who created it and from which session.
3. If unjustified, disable the account and review its group memberships and logons.

## LAB-008 - User Added to Privileged Group

An account was added to an administrative group (Administrators, Domain Admins, sudo...).

- **Type:** correlation  
- **Data sources:** windows_security, linux_auth  
- **Severity:** high  
- **ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation (Persistence)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Escalate if account created within (`recent_account_hours`) | 24 h | 1-168 |

**Logic**

```text
event_action = group_member_added AND group_name IN privileged_groups
| severity = critical if target account was created within 24 h
```

**Known false positives**

- Approved access request for a new administrator.

**Response**

1. Validate the access request / change ticket.
2. Remove the membership if not approved and investigate the actor's session.
3. Review privileged group changes across all hosts for the same period.

## LAB-009 - Suspicious PowerShell Execution

PowerShell launched with obfuscation, download or in-memory execution techniques.

- **Type:** behavioral  
- **Data sources:** windows_security, windows_powershell  
- **Severity:** high  
- **ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell (Execution)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Minimum indicator categories (`min_indicators`) | 2 | 1-6 |

**Logic**

```text
(event_id = 4688 AND process_name ends with powershell.exe) OR event_id = 4104
| score = count of indicator categories matched in command_line
|   (encoded command, download cradle, IEX, hidden window, bypass, AMSI, credential tooling)
| alert when score >= 2
```

**Known false positives**

- Software deployment / RMM tools that wrap scripts in -EncodedCommand.
- Administrators bootstrapping package managers (e.g. iwr ... | iex).

**Response**

1. Decode and review the full command / script block.
2. Check for network connections and files written by the process.
3. Isolate the host if a payload was downloaded or executed in memory.

## LAB-010 - Security Audit Log Cleared

The Windows Security event log was cleared (event 1102).

- **Type:** single_event  
- **Data sources:** windows_security  
- **Severity:** critical  
- **ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs (Defense Evasion)

**Logic**

```text
event_id = 1102
```

**Known false positives**

- Rare: decommissioning or re-imaging a host. Should always be backed by a change ticket.

**Response**

1. Treat as anti-forensics until proven otherwise.
2. Recover logs from the SIEM/forwarder for the period before the clear.
3. Investigate every session of the account that cleared the log.

## LAB-011 - Scheduled Task Created

A scheduled task was registered; severity rises when it runs an interpreter or a binary from a user-writable path.

- **Type:** single_event  
- **Data sources:** windows_security  
- **Severity:** medium  
- **ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task (Persistence)

**Logic**

```text
event_id = 4698
| severity = high if task command matches temp/appdata/public paths or cmd/powershell/rundll32/mshta
```

**Known false positives**

- Software installers and updaters that register maintenance tasks.

**Response**

1. Review the task action, trigger and author.
2. Collect the referenced binary/script and check its hash reputation.
3. Delete the task and the payload if malicious; hunt for the same task name on other hosts.

## LAB-012 - New Service Installed

A new Windows service was installed (7045/4697); common for persistence and remote execution tools.

- **Type:** single_event  
- **Data sources:** windows_system, windows_security  
- **Severity:** medium  
- **ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Create or Modify System Process: Windows Service (Persistence)

**Logic**

```text
event_id in (7045, 4697)
| severity = high if image path is user-writable or launches an interpreter
```

**Known false positives**

- Legitimate software installation or agent upgrades.

**Response**

1. Verify the service binary signature and hash.
2. Correlate with remote logons to the host just before the install (PsExec-like behaviour).
3. Stop and remove the service if unauthorized.

## LAB-013 - Lateral Movement: Logons to Multiple Hosts

The same account performs network or RDP logons to many distinct hosts in a short time.

- **Type:** threshold  
- **Data sources:** windows_security  
- **Severity:** high  
- **ATT&CK:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares (Lateral Movement); [T1021.001](https://attack.mitre.org/techniques/T1021/001/) Remote Services: Remote Desktop Protocol (Lateral Movement)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Distinct hosts (`distinct_hosts`) | 3 | 2-50 |
| Time window (`window_minutes`) | 10 min | 1-120 |

**Logic**

```text
event_id = 4624 AND logon_type in (3, 10) AND asset.role != 'Domain Controller'
| group by username
| alert when distinct(hostname) >= 3 within 10 min
```

**Known false positives**

- Backup, inventory or deployment service accounts that touch many servers by design.
- Administrators performing mass maintenance.

**Response**

1. Map the source host(s) of the logons and check if it is already compromised.
2. Look for service installs (LAB-012) or scheduled tasks (LAB-011) on the destinations.
3. Disable the account and isolate affected hosts if the activity is unexplained.

## LAB-014 - Sudo Privilege Escalation Attempt

A user not allowed to use sudo tried to run privileged commands, or failed sudo authentication repeatedly.

- **Type:** threshold  
- **Data sources:** linux_auth  
- **Severity:** medium  
- **ATT&CK:** [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Failed sudo password attempts (`max_failed_attempts`) | 3 | 1-20 |

**Logic**

```text
event_source = linux_auth AND (event_action = sudo_denied
  OR (event_action = sudo_auth_failed AND attempts >= 3))
| group by username, hostname within 30 min
```

**Known false positives**

- New team member who has not yet been granted sudo rights.

**Response**

1. Ask the user what they were trying to do and review the commands attempted.
2. If the account is shared or was recently compromised, reset it and review its SSH keys.

## LAB-015 - LSASS Memory Access

A non-system process opened lsass.exe with rights that allow reading its memory (credential dumping).

- **Type:** behavioral  
- **Data sources:** windows_sysmon  
- **Severity:** critical  
- **ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) OS Credential Dumping: LSASS Memory (Credential Access)

**Logic**

```text
event_source = windows_sysmon AND event_id = 10 AND fields.target_image ends with lsass.exe
| where fields.granted_access in (0x1010, 0x1410, 0x1438, 0x143a, 0x1fffff, ...)
| where process_name not in (MsMpEng.exe, csrss.exe, wininit.exe, services.exe, svchost.exe, ...)
```

**Known false positives**

- EDR / antivirus products and backup agents that legitimately read LSASS (allow-list them by signed path).
- Administrators running diagnostic tools such as Process Explorer.

**Response**

1. Isolate the host immediately: credentials of every account logged on to it must be considered stolen.
2. Collect the dumping binary and any dump file written to disk (Sysmon 11).
3. Reset passwords and revoke tickets for accounts with sessions on the host; hunt for their reuse elsewhere.

## LAB-016 - Threat Intelligence Indicator Match

An event references an IP, domain, URL or file hash listed in the threat-intelligence feed.

- **Type:** enrichment  
- **Data sources:** windows_security, windows_sysmon, windows_powershell, linux_auth  
- **Severity:** high  
- **ATT&CK:** [T1071](https://attack.mitre.org/techniques/T1071/) Application Layer Protocol (Command and Control)

**Logic**

```text
for each event: extract source/destination IP, DNS query, destination hostname,
  URLs (and their hosts) in command_line, SHA256 hash
| lookup threat_intel on (type, value)
| severity = indicator severity; one alert per indicator and host per hour
```

**Known false positives**

- Stale indicators: infrastructure is re-used or re-assigned after a campaign ends.
- Low-confidence feed entries (shared hosting, CDNs, Tor exit nodes used by legitimate users).

**Response**

1. Confirm the match in the raw event and check the indicator's confidence and age.
2. Block the indicator at the firewall / proxy / EDR and search for it across all hosts.
3. Investigate the process and account that produced the event on the affected host.

## LAB-017 - Office Application Spawned a Shell

An Office application started a command interpreter or LOLBin, typical of malicious macros.

- **Type:** single_event  
- **Data sources:** windows_security, windows_sysmon  
- **Severity:** high  
- **ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/) User Execution: Malicious File (Execution)

**Logic**

```text
event_action = process_created (4688 / Sysmon 1)
| where parent_process in (WINWORD, EXCEL, POWERPNT, OUTLOOK, ...)
|   AND process_name in (powershell, cmd, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin)
```

**Known false positives**

- Legacy business macros or add-ins that call scripts (they should be signed and documented).

**Response**

1. Identify the document that was opened and where it came from (mail, download, share).
2. Review the child process command line and everything it spawned or downloaded.
3. Quarantine the document organisation-wide and block macros in files from the internet (Mark of the Web).

## LAB-018 - Account Takeover Followed by PIX Transfer

A banking customer signed in from a device never seen for that account, changed contact data or registered a new PIX key / payee, and moved money shortly after.

- **Type:** correlation  
- **Data sources:** application  
- **Severity:** high  
- **ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts (Initial Access); [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation (Persistence); [T1657](https://attack.mitre.org/techniques/T1657/) Financial Theft (Impact)

**Tunable parameters**

| Parameter | Default | Range |
|---|---|---|
| Login-to-transfer window (`window_minutes`) | 30 min | 5-240 |
| Minimum transfer (`min_amount`) | 1000 BRL | 50-1000000 |

**Logic**

```text
event_source = application AND event_action = login_success AS l
| where l.fields.device_id not in (devices previously used by l.username)
| followed by event_action in (contact_changed, pix_key_registered, payee_added) AS c
| followed by event_action = pix_transfer AND fields.amount >= 1000 AS t
|   within 30 min of l, same username
```

**Known false positives**

- Customer replaced or reset the phone and paid someone new on the same day (look for a step-up or call-centre identity verification just before the login).
- Joint account holders sharing credentials from their own devices.

**Response**

1. Block outgoing PIX for the account and request MED (Mecanismo Especial de Devolução) for the transfers.
2. Revoke the new device's sessions, reset the credentials and contact the customer on a verified channel.
3. Hunt for the same source IP / device across other customers (credential stuffing campaigns hit many accounts).
4. Customer personal data was accessed by a third party: assess LGPD notification to ANPD and the data subject.
