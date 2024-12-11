# Password Sprayed Accounts (Locked and Failed logins)

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1110 | Brute Force | https://attack.mitre.org/techniques/T1110/ |

#### Description
Detect when multiple accounts are locked in your Azure tenant in a short timeframe, this can indicate brute force or password spray attacks. This detection is based on error code 50053 and 50126 which results from two different reasons:
- IdsLocked - The account is locked because the user tried to sign in too many times with an incorrect user ID or password. The user is blocked due to repeated sign-in attempts
- Sign-in was blocked or failed because it came from an IP address with malicious activity
  
## Defender XDR
```KQL
let failureCountThreshold = 3;
let timeRange = ago(1h);
let authWindow = 5m;
let sprayed_accounts = AADSignInEventsBeta
| where TimeGenerated >= timeRange
| extend FailureCondition = iff(ErrorCode == 50053 or ErrorCode == 50126, "Failure", "Success")
| where Application == "mssprinkler" or UserAgent contains "kali"
| summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated), ReportIDs = make_set(ReportId), 
failureCount=countif(FailureCondition=="Failure")
by bin(Timestamp, authWindow), AccountUpn, IPAddress, UserAgent
| where failureCount >= failureCountThreshold
| project AccountUpn, ReportIDs;
let accounts_expanded = sprayed_accounts | mv-expand ReportIDs to typeof(string);
AADSignInEventsBeta
| where TimeGenerated >= timeRange
| join accounts_expanded on $left.ReportId == $right.ReportIDs
```
