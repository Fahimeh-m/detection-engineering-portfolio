# Detection Engineering Portfolio

KQL detection rules for four common attacks on cloud identities and mailboxes, tested against synthetic logs with a hidden answer key.

The rules run on a free Azure Data Explorer cluster. KQL is the same query language used in Microsoft Sentinel, so the logic transfers to Sentinel analytics rules, but this project does not run on Sentinel. All companies, users, IPs and attacks are fictional.

## Results

Each rule was measured against an answer key that was never loaded into the cluster. Results are counted per incident, not per row.

| Rule | MITRE ATT&CK | Incidents | Alerts | Precision | Recall |
|---|---|---|---|---|---|
| Password spraying | T1110.003 | 1 | 1 | 100% | 100% |
| Impossible travel | T1078.004 | 5 | 5 | 100% | 100% |
| MFA fatigue | T1621 | 3 | 3 | 100% | 100% |
| Inbox forwarding to external domain | T1114.003 | 4 | 4 | 100% | 100% |

The alerts also named the same users and IPs as the answer key.

These scores are high because synthetic data has fewer look-alikes than real logs. The more useful result is what tuning changed:

| Rule | Before tuning | After tuning |
|---|---|---|
| Password spraying | 17 alerts for 1 attack (about 6% precision) | 1 alert for 1 attack |
| Impossible travel | VPN users took 4 of the top 10 speeds | 5 alerts for 5 attacks |
| MFA fatigue | 4 alerts for 3 attacks (fixed hourly windows split one attack) | 3 alerts for 3 attacks |

## Detections

| Rule | Logic | File |
|---|---|---|
| Password spraying | 10 or more distinct accounts failing from one IP within an hour, with a success rate under 10% | [`password_spraying.kql`](detections/password_spraying.kql) |
| Impossible travel | Successful sign-ins whose implied speed is over 900 km/h, excluding known VPN IPs, grouped per user per day | [`impossible_travel.kql`](detections/impossible_travel.kql) |
| MFA fatigue | 5 or more incomplete MFA prompts in a session window (15-minute gap). High if a success from the same IP follows within 30 minutes, otherwise Medium | [`mfa_fatigue.kql`](detections/mfa_fatigue.kql) |
| Inbox forwarding | New inbox rule forwarding outside the company domain. Severity depends on a policy switch and on whether the rule came from a known company IP | [`inbox_forwarding.kql`](detections/inbox_forwarding.kql) |

Each rule file documents its logic, thresholds, known false positives and limits.

## What tuning showed

**Password spraying.** Counting distinct accounts alone was not enough. Without a success-rate condition, normal morning sign-ins at the Oslo office produced 16 false alerts. Office hours had about 94% success; the attacker had none.

![Password spraying without the success-rate condition](docs/screenshots/07_password_spray_without_success_filter.png)

**Impossible travel.** The fastest "trip" was a normal user on the company VPN: Frankfurt, then Oslo one minute later. Excluding known VPN IPs and grouping per user per day left one alert per attack.

![Impossible travel before the VPN filter](docs/screenshots/08_impossible_travel_top_speeds.png)

![Final impossible travel rule](docs/screenshots/10_impossible_travel_final_rule.png)

**MFA fatigue.** Fixed one-hour windows split an attack that crossed the top of the hour. Session windows kept each burst together.

![Final MFA fatigue rule](docs/screenshots/11_mfa_fatigue_rule_result.png)

**Inbox forwarding.** Joining the mailbox log with sign-ins showed each forwarding rule was created by the same user and IP as an earlier compromised sign-in, so it is the next step of attacks the other rules found.

![Final inbox forwarding rule](docs/screenshots/14_inbox_forward_final_rule.png)

## Method

1. Generated 30 days of sign-in and mailbox logs for 1,000 fictional employees in Python (57,113 sign-ins, 44 mailbox events), with four planted attacks and normal activity that looks suspicious, such as VPN sign-ins and internal forwarding rules.
2. Wrote the answer key to a separate folder that is excluded from Git and was never loaded into the cluster.
3. Loaded the logs into Azure Data Explorer and checked row counts against the source files.
4. Wrote and tuned one KQL rule per attack.
5. Compared the rule results with the answer key in PowerShell.

## Limits

- The data is synthetic and cleaner than real logs. It has no normal MFA failures and no normal external forwarding, so precision on real logs is unknown for those two rules.
- A slow password spray spread over many hours or IPs can stay under the threshold.
- Impossible travel misses attackers who use the company VPN or the user's own city.
- MFA fatigue misses fewer than five prompts, long gaps between prompts, or IP changes.
- The MFA fatigue Medium level was not triggered in this data and is untested.

## Next

- [ ] Add normal MFA failures and normal external forwarding to the data for a fairer test
- [ ] Add one or two rules on real public attack logs
- [ ] Add an OT / power-grid security section

## Repository

- `notebooks/`: synthetic data generator
- `data/`: sign-in and mailbox logs
- `detections/`: KQL rules, one file per rule
- `docs/screenshots/`: query results from Azure Data Explorer

## Tools

KQL, Azure Data Explorer, Python, pandas, NumPy, PowerShell, Git, GitHub
