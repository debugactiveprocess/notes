# Using DuckDB for CTI and DFIR Investigations: Fast Local Analysis of IOCs, DNS, Connections, and Process Telemetry

In threat intelligence and incident response workflows, analysts routinely deal with fragmented data spread across CSV exports, JSON reports, sandbox outputs, DNS logs, connection telemetry, and endpoint process listings. In mature environments, those datasets may eventually land in a SIEM or data lake. But in many real-world investigations, the first phase happens locally: quickly triaging artifacts, correlating observables, testing hypotheses, and deciding whether a lead is worth escalating.

This is where DuckDB becomes extremely useful.

DuckDB is an in-process analytical database optimized for OLAP-style workloads. It requires no separate server, speaks standard SQL, and can query structured files such as CSV, JSON, and Parquet directly. For CTI, DFIR, malware triage, and network hunting, this makes DuckDB an excellent local investigation workbench.

The purpose of this article is to demonstrate how DuckDB can be used to correlate indicators of compromise (IOCs), DNS activity, connection logs, and process telemetry in a realistic malware investigation scenario. We'll cover why DuckDB is a strong fit for this workflow, how to structure investigation datasets, practical SQL queries, and a full example that pivots from a suspicious domain to impacted hosts and likely malware processes.

## Why DuckDB Fits CTI and DFIR Workflows

Threat investigations often begin with questions like:

- Which hosts resolved or connected to this suspicious domain?
- Which processes initiated those connections?
- Did multiple machines reach related infrastructure?
- Is this likely a one-off false positive or part of a broader campaign?
- Can I cluster related activity without standing up Elasticsearch, Splunk, or a full notebook stack?

DuckDB is particularly effective here for several reasons:

1. **Zero operational overhead**: No database server needs to be installed or maintained.
2. **Direct file querying**: Analysts can query `.csv`, `.json`, and `.parquet` files in place.
3. **SQL-first workflow**: Rapid pivots, joins, aggregations, and filtering are straightforward.
4. **Performance**: DuckDB handles large datasets efficiently, even on a local workstation.
5. **Interoperability**: It works well alongside Python, PowerShell, Jupyter, shell pipelines, and exported security telemetry.

For practical investigation work, DuckDB often sits in a useful middle ground:

- More scalable and expressive than Excel
- Lighter and faster to start with than a SIEM ingestion pipeline
- Simpler for structured correlation than writing ad hoc Python scripts for every pivot

## Typical Investigation Data Sources

The kinds of data that map cleanly into DuckDB during CTI or DFIR work include:

- DNS query logs exported from EDR, Zeek, Sysmon, or resolver infrastructure
- Netflow, proxy, firewall, or endpoint connection logs
- Process creation telemetry (e.g., Sysmon Event ID 1, EDR exports)
- Sandbox outputs from malware detonation environments
- IOC exports from OSINT, commercial feeds, or internal detection engineering
- Passive DNS and WHOIS enrichment exports
- Asset inventory data mapping hostnames to users, business units, or operating systems

In most cases, the data is already available in text-based formats. The bottleneck is not acquisition - it is correlation.

## Investigation Scenario: Suspicious Domain Found During Malware Triage

Let's work through a realistic example.

An analyst detonates a suspicious Windows sample in a sandbox and extracts the following indicators:

- Domain: `cdn-sync-updates[.]com`
- IPs: `45.77.154.32`, `104.21.88.210`
- HTTP path: `/api/v2/checkin`
- User-Agent: `Microsoft BITS/7.8`

At this stage, the analyst wants to answer five questions:

1. Have any internal hosts resolved this domain?
2. Which hosts connected to the associated IPs?
3. Which processes were responsible for those connections?
4. Is there related infrastructure contacted by the same systems?
5. Does the activity pattern look like malware beaconing?

We will model this investigation using four local files:

- `iocs.csv`
- `dns_logs.parquet`
- `conn_logs.parquet`
- `process_events.csv`

## Example Dataset Design

Below is a practical structure for each dataset.

### IOC dataset

```csv
value,type,tag,family,confidence
cdn-sync-updates.com,domain,C2,SampleX,high
45.77.154.32,ip,C2,SampleX,high
104.21.88.210,ip,FrontingCandidate,SampleX,medium
/api/v2/checkin,uri,BeaconPath,SampleX,medium
Microsoft BITS/7.8,user_agent,Masquerade,SampleX,medium
```

### DNS logs

```text
timestamp,host,query,query_type,response,answer_count
2026-07-17T10:14:00Z,WKSTN-004,cdn-sync-updates.com,A,NOERROR,2
2026-07-17T10:14:05Z,WKSTN-004,cdn-sync-updates.com,AAAA,NOERROR,0
2026-07-17T11:02:33Z,WKSTN-019,fonts-cache-service.com,A,NOERROR,1
```

### Connection logs

```text
timestamp,host,process_name,pid,remote_ip,remote_port,protocol,direction,bytes_sent,bytes_received
2026-07-17T10:14:08Z,WKSTN-004,svchost.exe,4120,45.77.154.32,443,TCP,outbound,584,1932
2026-07-17T10:19:09Z,WKSTN-004,svchost.exe,4120,45.77.154.32,443,TCP,outbound,601,1880
2026-07-17T10:24:10Z,WKSTN-004,svchost.exe,4120,45.77.154.32,443,TCP,outbound,590,1910
2026-07-17T11:02:36Z,WKSTN-019,chrome.exe,9984,104.21.88.210,443,TCP,outbound,1204,8922
```

### Process creation telemetry

```text
timestamp,host,pid,parent_pid,process_name,parent_process,command_line,user
2026-07-17T10:13:51Z,WKSTN-004,4120,980,svchost.exe,services.exe,svchost.exe -k netsvcs -p,ACME\jdoe
2026-07-17T10:13:49Z,WKSTN-004,7656,4212,rundll32.exe,explorer.exe,rundll32.exe C:\Users\jdoe\AppData\Roaming\cache\thumb.dll,Start,ACME\jdoe
2026-07-17T10:13:45Z,WKSTN-004,4212,3984,winword.exe,explorer.exe,"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" invoice.docm,ACME\jdoe
```

This model is intentionally realistic: the suspicious network activity is visible at the `svchost.exe` layer, but upstream process execution suggests a likely initial execution chain through `winword.exe` and `rundll32.exe`.

## Querying Files Directly with DuckDB

One of DuckDB's biggest strengths is that you can start investigating immediately without a formal import stage.

### Querying CSV and Parquet directly

```sql
SELECT *
FROM read_csv_auto('iocs.csv');

SELECT *
FROM read_parquet('dns_logs.parquet')
LIMIT 10;
```

If you prefer reusable names during a session, you can create views:

```sql
CREATE VIEW iocs AS
SELECT * FROM read_csv_auto('iocs.csv');

CREATE VIEW dns_logs AS
SELECT * FROM read_parquet('dns_logs.parquet');

CREATE VIEW conn_logs AS
SELECT * FROM read_parquet('conn_logs.parquet');

CREATE VIEW process_events AS
SELECT * FROM read_csv_auto('process_events.csv');
```

From that point onward, the investigation becomes a standard SQL workflow.

## Step 1: Match Known IOCs Against DNS Activity

The first pivot is simple: determine whether suspicious domains were resolved internally.

```sql
SELECT 
    d.timestamp,
    d.host,
    d.query,
    i.family,
    i.confidence
FROM dns_logs d
JOIN iocs i
    ON d.query = i.value
WHERE i.type = 'domain'
ORDER BY d.timestamp;
```

### Why this matters

This confirms exposure at the DNS layer, even if a connection was later blocked, failed, or happened over infrastructure not immediately obvious in connection logs. It also provides the earliest host-level pivot in many cases.

## Step 2: Match IP IOCs Against Outbound Connections

Once domain resolution is confirmed, pivot to network connections.

```sql
SELECT 
    c.timestamp,
    c.host,
    c.process_name,
    c.pid,
    c.remote_ip,
    c.remote_port,
    c.bytes_sent,
    c.bytes_received,
    i.family,
    i.tag
FROM conn_logs c
JOIN iocs i
    ON c.remote_ip = i.value
WHERE i.type = 'ip'
  AND c.direction = 'outbound'
ORDER BY c.timestamp;
```

### Interpretation

This shows whether the IOC progressed from a name-resolution event into actual outbound communication. If multiple hosts appear here, the case likely moves from isolated triage into wider incident scoping.

## Step 3: Correlate Suspicious Connections With Process Execution

Connection logs often identify the immediate process responsible for the socket, but not necessarily the full execution chain. Joining connection telemetry with process creation events helps reconstruct likely causality.

```sql
SELECT 
    c.timestamp AS conn_time,
    c.host,
    c.process_name,
    c.pid,
    c.remote_ip,
    p.parent_process,
    p.command_line,
    p.user
FROM conn_logs c
LEFT JOIN process_events p
    ON c.host = p.host
   AND c.pid = p.pid
WHERE c.remote_ip IN (
    SELECT value FROM iocs WHERE type = 'ip'
)
ORDER BY c.timestamp;
```

### Practical value

This query can reveal whether a suspicious connection came from:

- a browser process consistent with user activity
- a service host that might be masquerading malicious behavior
- a LOLBin such as `rundll32.exe`, `regsvr32.exe`, or `mshta.exe`
- a suspicious child process tied to a document, script engine, or archive utility

In malware investigations, this process context is often what turns a weak IOC match into a high-confidence finding.

## Step 4: Pivot From Impacted Hosts to Related Infrastructure

If one host contacted a known malicious IP, the next step is to determine whether the same host also reached other suspicious domains or IPs that may belong to the same campaign.

```sql
WITH impacted_hosts AS (
    SELECT DISTINCT host
    FROM conn_logs
    WHERE remote_ip IN (SELECT value FROM iocs WHERE type = 'ip')
)
SELECT 
    d.host,
    d.query,
    COUNT(*) AS dns_hits,
    MIN(d.timestamp) AS first_seen,
    MAX(d.timestamp) AS last_seen
FROM dns_logs d
JOIN impacted_hosts h
    ON d.host = h.host
GROUP BY d.host, d.query
ORDER BY d.host, dns_hits DESC;
```

### Why this pivot matters

Campaign infrastructure is often broader than the initial IOC set. A host that queried `cdn-sync-updates.com` may also have resolved fallback domains, tracking subdomains, staging infrastructure, or payload delivery endpoints not yet in your detection content.

This kind of host-centric expansion is one of the most useful CTI workflows DuckDB enables.

## Step 5: Detect Possible Beaconing Patterns

Malware C2 often produces recurring, low-volume outbound connections at regular intervals. Even a simple interval analysis can be useful.

```sql
SELECT 
    host,
    process_name,
    remote_ip,
    COUNT(*) AS connection_count,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen
FROM conn_logs
WHERE remote_ip IN (SELECT value FROM iocs WHERE type = 'ip')
GROUP BY host, process_name, remote_ip
HAVING COUNT(*) >= 3
ORDER BY connection_count DESC;
```

If you want to inspect intervals more closely:

```sql
SELECT 
    timestamp,
    host,
    process_name,
    remote_ip,
    LAG(timestamp) OVER (
        PARTITION BY host, process_name, remote_ip 
        ORDER BY timestamp
    ) AS previous_timestamp
FROM conn_logs
WHERE remote_ip IN (SELECT value FROM iocs WHERE type = 'ip')
ORDER BY host, process_name, remote_ip, timestamp;
```

With a little post-processing, this can highlight 5-minute, 10-minute, or jittered beacon intervals.

## Full Practical Example: From Suspicious Domain to Likely Infection Chain

Let's walk through the scenario using the example data.

### Initial observation

The sandbox report for a suspicious document-based sample yields:

- `cdn-sync-updates.com`
- `45.77.154.32`
- path `/api/v2/checkin`
- User-Agent `Microsoft BITS/7.8`

### First pivot: DNS matches

The domain query search returns:

```text
2026-07-17T10:14:00Z  WKSTN-004  cdn-sync-updates.com  SampleX  high
```

This confirms the sample infrastructure was contacted by an internal endpoint.

### Second pivot: connection match

The IP match returns multiple outbound connections from `WKSTN-004` to `45.77.154.32:443`.

```text
2026-07-17T10:14:08Z  WKSTN-004  svchost.exe  4120  45.77.154.32  443
2026-07-17T10:19:09Z  WKSTN-004  svchost.exe  4120  45.77.154.32  443
2026-07-17T10:24:10Z  WKSTN-004  svchost.exe  4120  45.77.154.32  443
```

At first glance, `svchost.exe` may appear benign. But periodic outbound traffic from the same PID suggests a service-hosted or service-masqueraded beacon.

### Third pivot: process correlation

Correlating PID `4120` on `WKSTN-004` with process telemetry reveals nearby suspicious activity:

```text
2026-07-17T10:13:45Z  winword.exe   opened invoice.docm
2026-07-17T10:13:49Z  rundll32.exe  executed thumb.dll from AppData\Roaming\cache
2026-07-17T10:13:51Z  svchost.exe   running in user context ACME\jdoe
```

This sequence strongly suggests:

1. The user opened a malicious Office document.
2. The document launched a DLL through `rundll32.exe`.
3. The malicious chain established persistence or process migration.
4. A recurring outbound C2 channel was then established to `45.77.154.32`.

### Fourth pivot: related infrastructure

Reviewing all DNS activity for `WKSTN-004` in the surrounding time window may expose additional domains associated with the same malware family, enabling enrichment and clustering.

For example:

```text
cdn-sync-updates.com
assets-win-service.net
api-edge-status.com
```

Even if only one of these domains is in the initial IOC set, the others may become valuable leads for:

- retro-hunting across historical telemetry
- pivoting in passive DNS datasets
- building broader blocklists or detections
- clustering infrastructure by registrar, ASN, TLS, or naming patterns

## Using DuckDB for IOC Enrichment and Clustering

DuckDB is also useful when the goal is not only validation but expansion.

Suppose you maintain a second dataset with enrichment context:

```csv
observable,asn,country,registrar,first_seen,last_seen
cdn-sync-updates.com,AS13335,US,NameCheap,2026-07-10,2026-07-19
assets-win-service.net,AS13335,US,NameCheap,2026-07-10,2026-07-19
api-edge-status.com,AS13335,US,NameCheap,2026-07-11,2026-07-19
```

You can quickly identify likely infrastructure clusters:

```sql
SELECT 
    registrar,
    asn,
    COUNT(*) AS observable_count,
    LIST(observable) AS observables
FROM enrichment
GROUP BY registrar, asn
HAVING COUNT(*) >= 2;
```

This kind of clustering is simple but operationally valuable. It helps analysts move from isolated IOCs to infrastructure-level intelligence.

## Comparison With Other Investigation Approaches

### DuckDB vs Excel

DuckDB is far superior once the dataset grows or correlation requires joins, grouping, or time-based pivots.

### DuckDB vs SQLite

SQLite is excellent for transactional embedded workloads, but DuckDB is generally stronger for analytical investigation patterns, columnar execution, and direct querying of Parquet.

### DuckDB vs pandas

Pandas is flexible, but many investigation tasks are easier to express as SQL joins and aggregations. DuckDB also reduces the amount of boilerplate required for local triage.

### DuckDB vs SIEM

A SIEM remains essential for centralized enterprise-scale telemetry. But for rapid, local, analyst-driven investigation and enrichment, DuckDB is often faster to start and easier to iterate with.

## Operational Tips for Investigators

To make DuckDB genuinely useful in day-to-day CTI and DFIR work, consider the following practices:

1. **Normalize timestamp fields early** so cross-source joins are easier.
2. **Standardize host naming** if exports come from multiple tools.
3. **Preserve raw datasets** and create views rather than mutating source evidence.
4. **Separate IOC seeds from enriched observables** so your pivots remain explainable.
5. **Use Parquet when possible** for better performance on larger datasets.
6. **Store investigation queries** in `.sql` files so hunts are reproducible.

## Limitations and Caveats

DuckDB is powerful, but there are important limitations:

1. **It is not a SIEM replacement**: it does not provide native alerting, collection, or enterprise-scale retention.
2. **Data quality still matters**: poor exports, inconsistent schemas, and weak timestamps can mislead analysis.
3. **Context remains analyst-driven**: SQL can correlate observables, but it cannot replace reasoning about tradecraft and false positives.
4. **Very large distributed datasets may require other platforms** if the investigation expands beyond local scope.

Even so, for focused investigation, malware triage, IOC validation, and local enrichment, DuckDB provides an exceptional balance between speed, simplicity, and analytical power.

## Conclusion

DuckDB is one of the most useful underused tools for CTI and DFIR investigations. It gives analysts a fast local SQL engine capable of correlating IOC lists, DNS logs, connection telemetry, process events, and enrichment datasets without the friction of building a full ingestion pipeline.

In practical investigations, this means you can move quickly from a suspicious domain or IP to:

- impacted hosts
- responsible processes
- likely execution chains
- related infrastructure
- candidate beaconing patterns

For malware triage, retro-hunting, and small-to-medium-scope incident investigations, DuckDB is not just convenient - it is strategically effective.

If your current workflow still relies on spreadsheets, ad hoc scripts, or manual pivots across disconnected exports, adding DuckDB to your toolkit can significantly improve both investigation speed and analytical depth.

## References

- **DuckDB Documentation**: [https://duckdb.org/docs/](https://duckdb.org/docs/)
- **DuckDB SQL Introduction**: [https://duckdb.org/docs/stable/sql/introduction](https://duckdb.org/docs/stable/sql/introduction)
- **DuckDB CSV Import / Query**: [https://duckdb.org/docs/stable/data/csv/overview](https://duckdb.org/docs/stable/data/csv/overview)
- **DuckDB Parquet Overview**: [https://duckdb.org/docs/stable/data/parquet/overview](https://duckdb.org/docs/stable/data/parquet/overview)
- **MITRE ATT&CK**: [https://attack.mitre.org/](https://attack.mitre.org/)

*(Note: The investigation scenario and sample dataset in this article are representative and designed to reflect realistic malware-analysis workflows. Adapt the schemas and pivots to your own telemetry sources.)*