# Detection Engineering Portfolio

I am building KQL detection rules for attacks on cloud accounts and measuring how well they work. This is a personal learning project. The company, employees and attacks are all fictional, and no real personal data is used.

The rules run on an Azure Data Explorer free cluster. KQL is the same query language used in Microsoft Sentinel, but this project does not run on Sentinel.

## Status

- [x] Free Azure Data Explorer cluster and private repository
- [x] Synthetic sign-in and mailbox logs with four planted attacks
- [x] Logs loaded into Azure Data Explorer and row counts checked
- [x] Detection rule for password spraying
- [x] Detection rule for impossible travel
- [ ] Detection rule for MFA fatigue
- [ ] Detection rule for suspicious inbox forwarding
- [ ] Measure each rule against the answer key (precision and recall)
- [ ] Add one or two rules on real public attack logs
- [ ] Add an OT / power-grid security section

## Day 1 (5 November 2026)

Today I set up the project and built the data.

I generated logs for 1,000 fictional employees over 30 days in September 2026. I planted password spraying, impossible travel, MFA fatigue and a suspicious inbox forwarding rule. I also added normal VPN sign-ins and normal inbox rules, because a rule should be tested on activity that only looks suspicious.

The answer key stays on my own computer and is not in this repository, so each rule has to find the attacks from behaviour alone.

After loading the data, I compared the row counts with the source files: 57,113 sign-ins and 44 mailbox events.

![Sign-in row count](docs/screenshots/01_signin_logs_count.png)

![Mailbox event row count](docs/screenshots/02_office_activity_count.png)

## Day 2 (6 November 2026)

### Password spraying

Password spraying (MITRE ATT&CK T1110.003) means trying one or a few common passwords against many accounts, once each. It is designed to avoid account lockout, because no single account fails often enough to be locked.

My first attempt simply counted failed sign-ins (ResultType 50126) per IP. It did not work well. The four office IPs ranked above the attacker, because 1,000 employees mistype their passwords now and then over a month.

![Failed sign-ins per IP](docs/screenshots/03_password_spray_naive_count.png)

Next I counted how many different accounts each IP failed on within one hour. With a threshold of 20, only the attacker was left: 150 different accounts in one hour.

![Distinct accounts per hour](docs/screenshots/04_password_spray_rule_result.png)

Before trusting that threshold, I checked how close normal traffic came to it. The busiest office hour in Oslo reached 15 accounts, which felt too close to 20.

![Highest hourly count per IP](docs/screenshots/05_password_spray_threshold_check.png)

Raising the threshold would hide slower attackers, so I added a second condition instead: almost no successful sign-ins from that IP in the same hour. Office hours had about 94% success, while the attacker had none. With both conditions I could lower the threshold to 10 and still get only the attack.

![Final rule result](docs/screenshots/06_password_spray_final_rule.png)

To check that the second condition really matters, I removed it. The same threshold then returned 17 alerts, and 16 of them were normal morning sign-ins at the Oslo office.

![Without the success-rate filter](docs/screenshots/07_password_spray_without_success_filter.png)

The rule is in `detections/password_spraying.kql`.

### Impossible travel

Impossible travel (MITRE ATT&CK T1078.004) means the same account signs in from two places that are too far apart for the time between them. It usually means someone else has the password, so this rule only looks at successful sign-ins.

The logs only have city names, so I added a small table with approximate coordinates for each city. For every user, I compared each successful sign-in with the previous one and calculated the distance and the implied travel speed.

The fastest "trip" was not an attack. It was a normal user who signed in through the company VPN in Frankfurt and then from Oslo one minute later, which looks like 54,900 km/h. Three more VPN users also showed up among the top ten.

![Top travel speeds before the VPN filter](docs/screenshots/08_impossible_travel_top_speeds.png)

A company knows its own VPN addresses, so I excluded the VPN IP and kept only trips faster than 900 km/h, roughly the speed of a passenger plane. That left six rows: five sign-ins from Singapore about 25 minutes after a sign-in in Norway, and one return trip when the real user signed in again in Stavanger.

![Rule result after the VPN filter](docs/screenshots/09_impossible_travel_rule_result.png)

One attack should give one alert, so I grouped the results into one alert per user per day. The final rule returns five alerts for five attacks. The Legs column shows that one of them had two parts: the trip to Singapore and the trip back.

![Final rule result](docs/screenshots/10_impossible_travel_final_rule.png)

The rule is in `detections/impossible_travel.kql`.

Both rule files include notes on the logic, thresholds, known false positives and limits. Precision and recall against the answer key will come once all four rules are written.

## Repository

- `notebooks/`: the notebook that generates the synthetic data
- `data/`: the sign-in and mailbox logs
- `detections/`: KQL rules, one file per rule
- `docs/screenshots/`: screenshots from Azure Data Explorer

## Limits

The data is synthetic and simpler than real logs. Good results here show the method, not how the rules would perform in a real company.

An attacker who spreads attempts over many hours or many IPs can stay under the password spraying threshold.

The impossible travel rule does not see an attacker who signs in through the company VPN or from the same city as the user. City coordinates are approximate, and two separate attacks on one user on the same day become one alert.

## Tools

Python, pandas, NumPy, KQL, Azure Data Explorer, Git, GitHub
