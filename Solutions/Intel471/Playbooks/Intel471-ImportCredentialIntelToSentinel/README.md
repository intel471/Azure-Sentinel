# Intel 471 Credential Intelligence import to Sentinel

## Table of contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Getting your Intel 471 API credentials](#getting-your-intel-471-api-credentials)
4. [What the template creates](#what-the-template-creates)
5. [Storage account requirements](#storage-account-requirements)
6. [Deployment instructions](#deployment-instructions)
7. [Post-deployment instructions](#post-deployment-instructions)
8. [Adding Verity API filters](#adding-verity-api-filters)
9. [How paging and the cursor work](#how-paging-and-the-cursor-work)
10. [Querying credential data in Sentinel](#querying-credential-data-in-sentinel)
11. [Filtering by GIR](#filtering-by-gir)
12. [Table schema and data mapping](#table-schema-and-data-mapping)
13. [Volume and cost](#volume-and-cost)
14. [Troubleshooting](#troubleshooting)

## Overview

This playbook fetches compromised credential occurrences from the Intel 471
[Verity 471 Credentials API](https://developer.intel471.com) and writes them into a custom Log Analytics
table, `Intel471CredentialOccurrences_CL`, using the
[Azure Monitor Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview).

Each row is **one sighting of one credential**: the login, the monitored domain that matched it, password
strength and complexity metadata, the credential set it was found in, and - where the credential came from an
information stealer rather than a combination list - the malware family and the infected host that captured it.

**Plaintext passwords are never ingested.** Log Analytics has no column-level access control, so a plaintext
password column would be readable by anyone with workspace read access. The playbook does not map
`password_plain` and the table has no column for it. Password strength, length, entropy, score, weakness and
per-character-class counts *are* ingested, which covers password-policy reporting and filtering.

This is a different shape of data from the companion
[Intel 471 Malware Intelligence playbook](../Intel471-ImportMalwareIntelligenceToSentinel/README.md).
Malware indicators are IOCs to match traffic against, so they go into Sentinel's built-in threat intelligence
tables. A compromised credential is an *observation about your own users*, not something to match network
traffic against, so it belongs in a log table you query and join against sign-in data.

[azuredeploy.json](azuredeploy.json) is an Azure Resource Manager template (ARM template) that builds
everything needed:

- **[Logic App](https://docs.microsoft.com/azure/sentinel/create-custom-connector#connect-with-logic-apps)**
  that pages through the Verity credential-occurrence stream on a schedule and posts the results.
- **Custom table** `Intel471CredentialOccurrences_CL` in the Log Analytics workspace you nominate.
- **Data collection endpoint** (`dce-intel471-creds`) and **data collection rule** (`dcr-intel471-creds`) -
  the typed doorway into that table.
- Two connection objects, both authenticating with the logic app's system-assigned managed identity, so no
  credentials or keys are stored in them:
  - Logic app to Blob storage
  - Logic app to Key Vault

  Each needs a **role assignment** after deployment - see
  [Post-deployment instructions](#post-deployment-instructions).

There is deliberately **no Microsoft Sentinel connection**: this playbook writes to its own table over the
Logs Ingestion API rather than through the threat intelligence connector.

> **Note:** installing the Intel 471 solution from the Microsoft Sentinel **Content hub** does not create the
> logic app. The solution installs the playbook *templates*; the logic app is created when you deploy a
> playbook from `Content hub` → `Intel 471` → `Manage` → `Create playbook`, or from
> `Microsoft Sentinel` → `Automation` → `Playbook templates`. Deploying [azuredeploy.json](azuredeploy.json)
> directly, as described below, creates it in one step.

## Prerequisites

1. An active account in the Verity 471 platform, which is available as part of Intel 471's subscriptions. For
   more information, please contact sales@intel471.com. **Credential Intelligence must be included in your
   subscription**, and the domains you want monitored must already be registered with Intel 471 - the API
   returns credentials for *your* monitored domains, so an account without registered domains returns nothing.
2. Verity API credentials - see
   [Getting your Intel 471 API credentials](#getting-your-intel-471-api-credentials).
3. Pre-existing [Key Vault](https://docs.microsoft.com/azure/key-vault/general/basic-concepts) for securely
   storing the API credentials. By default the playbook reads:

    | Credential | Key Vault secret |
    | ---------- | ---------------- |
    | Verity API Client ID | `VerityUserNameSentinel` |
    | Verity API Client Secret | `VerityAPIKeySentinel` |

    These are the same secret names the Malware Intelligence playbook uses, so if you already run that
    playbook there is nothing new to store. If your organisation keeps these credentials under different
    names, leave the secrets where they are and pass the *names* of those secrets in the optional
    `KeyVaultUsernameSecretName` and `KeyVaultApiKeySecretName` deployment parameters instead. Those two
    parameters take secret names, never credential values.
4. Pre-existing [Storage account](https://docs.microsoft.com/azure/storage/blobs/storage-blobs-introduction)
   with a blob container, for persisting the stream cursor between runs. Default settings are fine - see
   [Storage account requirements](#storage-account-requirements). It can be the same container the Malware
   Intelligence playbook uses; the blob names do not collide.
5. The **name and resource group of the Log Analytics workspace** that will hold the data. Nothing needs to be
   prepared inside the workspace - the template creates the table, the endpoint and the rule.

## Getting your Intel 471 API credentials

The playbook authenticates to the Intel 471 API with HTTP Basic authentication. Verity issues an
**API Client ID** and an **API Client Secret**. There is no separate "user name" or "API key" to look for -
the Client ID is sent as the Basic user name and the Client Secret as the Basic password. Store them like
this:

| Verity portal value | Key Vault secret (default name) |
| ------------------- | ------------------------------- |
| API Client ID       | `VerityUserNameSentinel`        |
| API Client Secret   | `VerityAPIKeySentinel`          |

To obtain them, sign in to the Intel 471 portal, open your account/API settings and create an API client.
Copy the Client Secret at creation time - it is not shown again. If you do not see the option, or the stream
returns `403`, your subscription may not include Credential Intelligence API access; contact
[support@intel471.com](mailto:support@intel471.com).

Do not swap the two values - a reversed pair is the most common cause of a `401` from the API.

## What the template creates

| Resource | Name | Purpose |
| --- | --- | --- |
| Custom table | `Intel471CredentialOccurrences_CL` | Where the data lands. Created in the workspace's resource group via a nested deployment, so the workspace may live in a different resource group from the playbook. |
| Data collection endpoint | `dce-intel471-creds` | The HTTPS address the logic app posts to. |
| Data collection rule | `dcr-intel471-creds` | Declares the incoming stream `Custom-Intel471CredentialOccurrences_CL`, its 40 typed columns, and the workspace destination. Passes data through unchanged (`transformKql: "source"`). |
| API connection | `azureblob-<PlaybookName>` | Reads and writes the cursor blob. Managed identity. |
| API connection | `keyvault-<PlaybookName>` | Reads the two credential secrets. Managed identity. |
| Logic app | `<PlaybookName>` | The connector itself. System-assigned identity. |

The template's outputs give you the values needed for the post-deployment role assignments:
`logicAppPrincipalId`, `dataCollectionRuleId`, `dataCollectionEndpoint` and `tableName`.

## Storage account requirements

Any storage account with a blob container works, with default settings. The playbook keeps its position in
the Intel 471 credential stream in two small text blobs there: it reads them at the start of every run,
creates them if they are missing, and overwrites the cursor blob as it pages through results. Nothing else is
written.

| Blob | Name | Written |
| ---- | ---- | ------- |
| Cursor | `cursorCredentialsVerity.txt` | On every page, as `<filter set>\|<cursor>` |
| From-date | `fromdateCredentialsVerity.txt` | On first run, and again whenever the filter set changes |

These names are distinct from the Malware Intelligence playbook's blobs, so both playbooks can share one
container safely.

The playbook authenticates with the logic app's system-assigned managed identity, so no account key or
connection string is involved. It needs the `Storage Blob Data Contributor` role on the storage account - see
[Post-deployment instructions](#post-deployment-instructions). Contributor rather than Reader, because it
writes the cursor blob.

Two things in your environment can stop it working:

- **A storage firewall.** If `Public network access` is set to `Enabled from selected virtual networks and IP
  addresses`, also tick **Allow Azure services on the trusted services list to access this storage account**
  under `Networking` → `Exceptions`. `Microsoft.Logic/workflows` is on that
  [trusted services list](https://learn.microsoft.com/azure/storage/common/storage-network-security-trusted-azure-services).
  If a run still returns `403` right after you enable it, toggle the exception off, save, then on, and save
  again - that is a
  [documented quirk](https://learn.microsoft.com/azure/connectors/connectors-create-api-azureblobstorage#configure-storage-account-access),
  not a misconfiguration.
- **A lifecycle management rule that archives blobs.** The from-date blob is written once and rarely updated,
  so a rule keyed on last-modified date will eventually move it to the Archive tier. An archived blob cannot
  be read and the run fails. Exclude the two blobs above from any such rule.

If a blob read fails for any reason other than "blob does not exist", the run terminates with
`CursorBlobUnreadable` or `FromDateBlobUnreadable` and the HTTP status in the message. The two errors worth
recognising are `AuthorizationPermissionMismatch` - the `Storage Blob Data Contributor` assignment is missing
or has not propagated yet, which is the expected failure immediately after deploying - and `This request is
not authorized to perform this operation.`, which is the storage firewall.

## Deployment instructions

1. To deploy the Playbook, click the **Deploy to Azure** button. It will launch the ARM Template deployment
   wizard.
2. Provide following parameters:
    * **Playbook Name**: Either leave the default one or change it as needed
    * **StorageAccountName**: Name of the Storage account (see prerequisites)
    * **StorageAccountContainerName**: Name of the blob container in the Storage account
    * **KeyVaultName**: Name of the Key Vault holding the credentials (see prerequisites). The credentials
      themselves are never entered on this screen - they must already be stored as secrets in that Key Vault.
    * **KeyVaultUsernameSecretName** *(optional, leave empty)*: Only needed if your Key Vault stores the
      credential under a name other than the default. This is the **name of a Key Vault secret**, not the
      credential value - do not paste your Verity Client ID here. Empty uses `VerityUserNameSentinel`.
    * **KeyVaultApiKeySecretName** *(optional, leave empty)*: As above for the API key secret. Empty uses
      `VerityAPIKeySentinel`.
    * **WorkspaceName**: **Name** of the Log Analytics workspace that will hold the custom table - not the
      workspace ID. The companion Malware Intelligence playbook asks for the workspace **ID** (the GUID)
      because the Sentinel threat-intelligence connector addresses the workspace by GUID in its API path.
      This playbook instead has to build the workspace's **ARM resource ID**, which is composed of
      subscription, resource group and name, in two places: the data collection rule's `logAnalytics`
      destination, and the nested deployment that creates the custom table. There is no ARM function that
      resolves a workspace GUID to its resource ID, so the name is required. Workspace name is also the
      convention Content Hub itself uses for solution templates.
    * **WorkspaceResourceGroup** *(optional, leave empty)*: Resource group of that workspace. Empty means the
      resource group you are deploying into.
    * **TableRetentionInDays**: Retention for the custom table. Leave `-1` to inherit the workspace default.
    * **LookBackDays**: How many days of history should be pulled on the first run. Leave 0 to start from the
      current time. Credential occurrences are high volume - see [Volume and cost](#volume-and-cost).
    * **MigrationMarginHours**: Safety margin applied when the playbook detects that its request filters
      changed. Leave at 1 unless you are deliberately widening what is ingested.
    Instead of typing the values in, you can supply them all at once from a file: on the **Custom deployment**
    screen select **Edit parameters** → **Load file** and use
    [azuredeploy.parameters.json](azuredeploy.parameters.json) as a starting point.

    [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FIntel471%2FPlaybooks%2FIntel471-ImportCredentialIntelToSentinel%2Fazuredeploy.json)
    [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2FAzure-Sentinel%2Fmaster%2FSolutions%2FIntel471%2FPlaybooks%2FIntel471-ImportCredentialIntelToSentinel%2Fazuredeploy.json)

## Post-deployment instructions

All three grants are required. **These steps also apply when you redeploy** - see the warning at the end of
this section.

1. Grant the logic app read access to the Key Vault secrets. **Check the Key Vault's permission model first**
   (Key Vault → `Access configuration`), because the two models need different steps and granting the wrong
   one silently results in `403 Forbidden` on every run:

    * **Azure role-based access control**: Key Vault → `Access control (IAM)` → `+ Add` →
      `Add role assignment` → `Key Vault Secrets User` → `+ Select members`, search for Intel 471, select the
      newly created logic app and grant access.
    * **Vault access policy** (legacy): Key Vault → `Access policies` → `+ Create` → tick the `Get` secret
      permission → select the newly created logic app as principal → `Create`. A `Key Vault Secrets User`
      role assignment has **no effect** on a vault in this mode.

2. Go to the storage account, then `Access control (IAM)` → `+ Add` → `Add role assignment` and grant the
   logic app the **`Storage Blob Data Contributor`** role. Contributor rather than Reader, because the
   playbook writes the cursor blob. Without this the run fails with `CursorBlobUnreadable` and an
   `AuthorizationPermissionMismatch` error.

3. Go to the data collection rule **`dcr-intel471-creds`** (Monitor → `Data collection rules`, or find it in
   the resource group), then `Access control (IAM)` → `+ Add` → `Add role assignment` and grant the logic app
   the **`Monitoring Metrics Publisher`** role. Without this every run fails at the `PostToDcr` step with
   `403 Forbidden`. The role name mentions metrics for historical reasons; it is the logs-ingestion role.

    ⚠️ **Azure documents up to 30 minutes for this assignment to take effect**, and sending data before then
    returns `403` with no other symptom. Verify the assignment once, then wait - do not conclude it failed and
    start changing things. See [Troubleshooting](#troubleshooting).

4. Optionally change the logic app's schedule frequency in the `Recurrence` block (the first one).

5. Optionally add API filters - see [Adding Verity API filters](#adding-verity-api-filters).

> ⚠️ **A redeploy that recreates the logic app or the data collection rule invalidates the grants.**
> Recreating the logic app issues it a **new** managed identity, and Azure garbage-collects the old identity's
> role assignments. Recreating the DCR changes its immutable ID and drops its assignments with it. A plain
> `az deployment group create` over an existing deployment updates in place and keeps both; deleting resources
> in the portal first, or deploying in Complete mode, does not. After any redeploy, if you get a `403`, check
> whether the logic app's `identity.principalId` still matches the principal in the role assignment.

## Adding Verity API filters

The Credentials API supports a rich filter set, and **any of its query parameters can be passed through**
without editing the template. Filters live in one place: the `payload` variable initialised in the
**`InitVariables`** action. Out of the box it contains only the page size:

```json
{ "size": 100 }
```

Open the logic app in the designer, edit that variable, and add whatever the API accepts as further keys. The
`HTTP` action sends every key/value in `payload` verbatim as a query parameter, layering the from-date and the
cursor on top at request time.

Two keys are managed by the playbook and should **not** be put in `payload`: `cursor`, and `from` - the
from-date, which the playbook tracks in its blob. Note that `from` filters on the credential's **activity**
time while the stream is ordered and cursored by `last_updated_ts`; that mismatch is why
`MigrationMarginHours` exists, and it is the same arrangement the Malware Intelligence playbook uses.

Useful filters for credentials:

| Query parameter | Example | Effect |
| --- | --- | --- |
| `affiliation_group` | `my_employees` | Restrict to `my_employees`, `my_customers`, `third_parties` or `vip_emails`. The single most effective volume control. |
| `password_strength` | `weak` | `excellent`, `strong`, `medium`, `weak`, `poor`, `not_provided` |
| `password_length_gte` | `12` | Only credentials whose password is at least this long |
| `password_entropy_gte` | `40` | Only credentials above this entropy |
| `detected_malware` | `Lumma` | Only occurrences captured by a given stealer family |
| `domain` | `example.com` | Restrict to one detection domain |
| `girs` | `4.2.2` or `my_girs,company_pirs` | Restrict by General Intelligence Requirement. Accepts explicit GIR paths, or the aliases `my_girs` and `company_pirs` to use the requirements configured on your account. See [Filtering by GIR](#filtering-by-gir). |

The full list is in the Credentials API specification on the
[Intel 471 developer portal](https://developer.intel471.com).

> ⚠️ **Changing a filter invalidates the stored cursor**, because a Verity cursor is only valid for the exact
> filter set it was issued against. The playbook handles this rather than silently skipping records: it
> records the filter set alongside the cursor, notices the mismatch on the next run, discards the cursor and
> rewinds the from-date by `MigrationMarginHours`. Expect a one-off overlapping re-ingest and look for
> `Intel471FilterSetChanged` in the run history. If the change *widens* what is ingested and you want history
> for the newly included data, raise `MigrationMarginHours` for that one run.

**Do not raise `size` much above a few hundred.** The whole page is posted to the Logs Ingestion API in a
single request, and that API caps a request at 1 MB. A `413` from `PostToDcr` means the page was too large.

## How paging and the cursor work

The behaviour is identical to the Malware Intelligence playbook version 3.1, and the action names are kept
the same on purpose so the two templates can be diffed against each other.

1. `GetUsername` / `GetApiKey` read the two secrets from Key Vault.
2. `InitVariables` sets up the `payload` (your filters) and the loop state.
3. `ComputeFilterSetMarker` renders the filter set to a string - this is what makes a filter change detectable.
4. `GetCursorFromBlob` / `GetFromDateFromBlob` load where the last run stopped, creating the blobs on first
   run. Any read failure other than "not found" terminates the run with a clear error rather than sending
   garbage to the API.
5. `IfFilterSetChanged` compares the stored filter set against the current one, and migrates as described
   above if they differ.
6. `CollectAndSubmitOccurrences` pages the stream until it drains: `HTTP` → `Parse_JSON` → `SetHasResults` →
   `MapOccurrences` → `PostToDcr` → **then** `StoreCursor`.
7. `IfUploadFailed` terminates the run with `CredentialUploadFailed` if any page failed to post.

Two properties are worth understanding, because they are what makes the connector safe to run unattended:

- **The cursor is stored only after a page has been written.** If the post fails, the cursor is not advanced
  and the next run replays that page. This is at-least-once delivery: a page can be delivered twice, never
  skipped.
- **A failed post stops the loop and fails the run.** Without this, a failed iteration would be masked by the
  following one and the run would report success while losing data.

The cursor blob holds `<filter set>|<cursor>` rather than a bare cursor. A blob written by hand or by an older
version is read as an unknown filter set and triggers the migration on the next run.

## Querying credential data in Sentinel

Go to **Microsoft Sentinel → Logs**, or the workspace's **Logs** blade. The table appears in the schema tree
under **Custom Logs**.

> ⚠️ **`TimeGenerated` is the time the playbook ingested the row, not the time the credential was seen.**
> Azure Monitor overwrites any supplied `TimeGenerated` that is more than two days older than the receipt
> time, so using it for the observation time would make the column mean one thing for fresh data and another
> for backfilled data. The observation times are in `LastUpdatedTime`, `FirstSeenTime`, `LastSeenTime` and
> `InfectionTime`. Filter on those when you mean "when was this credential compromised", and on
> `TimeGenerated` when you mean "what did we learn recently". The difference between the two is a useful
> detection-latency measure in its own right.

First 20 ingested occurrences:

```kusto
Intel471CredentialOccurrences_CL | take 20
```

Employee credentials learned about in the last day, with detection latency:

```kusto
Intel471CredentialOccurrences_CL
| where TimeGenerated > ago(1d) and Affiliations has "my_employees"
| extend DetectionLatency = TimeGenerated - LastUpdatedTime
| project LastUpdatedTime, DetectionLatency, CredentialLogin, AccessedDomain, MalwareFamily, PasswordStrength
| order by LastUpdatedTime desc
```

Infostealer-infected hosts, grouped by machine:

```kusto
Intel471CredentialOccurrences_CL
| where isnotempty(MachineId)
| summarize Credentials = dcount(CredentialId), Logins = make_set(CredentialLogin, 10),
            FirstSeen = min(FirstSeenTime), LastSeen = max(LastSeenTime)
    by MachineId, PcName, ComputerUsername, MalwareFamily, SourceIP, OperatingSystem
| order by Credentials desc
```

Credentials that fail your password policy:

```kusto
Intel471CredentialOccurrences_CL
| where PasswordStrength in ("poor", "weak") or PasswordLength < 12
| summarize arg_max(LastUpdatedTime, *) by CredentialId
| project LastUpdatedTime, CredentialLogin, PasswordStrength, PasswordLength, PasswordEntropy
```

Shared passwords - credential-stuffing candidates:

```kusto
Intel471CredentialOccurrences_CL
| where isnotempty(PasswordId)
| summarize Accounts = dcount(CredentialLogin), Logins = make_set(CredentialLogin, 20) by PasswordId
| where Accounts > 1
| order by Accounts desc
```

Join against Entra ID sign-ins to see whether an exposed credential was actually used:

```kusto
Intel471CredentialOccurrences_CL
| where Affiliations has "my_employees"
| distinct CredentialLogin, LastUpdatedTime
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | project UserPrincipalName = tolower(UserPrincipalName), SigninTime = TimeGenerated, IPAddress, AppDisplayName
  ) on $left.CredentialLogin == $right.UserPrincipalName
| where SigninTime > LastUpdatedTime
| project CredentialLogin, LastUpdatedTime, SigninTime, IPAddress, AppDisplayName
```

### Two query traps

**Deduplicate before counting.** The API can return several occurrences of the same credential, sometimes with
identical content and different `OccurrenceId`s - a known upstream issue - and at-least-once retry can add
more. Rows are *sightings*, not unique credentials:

```kusto
Intel471CredentialOccurrences_CL
| summarize arg_max(LastUpdatedTime, *) by CredentialId, CredentialSetId, AccessedDomain
```

**Never filter GIRs with `has`** - see [Filtering by GIR](#filtering-by-gir) for why, and what to do instead.

## Filtering by GIR

General Intelligence Requirements classify why a record is relevant. Each one has a dotted **path** (the ID,
e.g. `4.2.2`) and a **name** (e.g. `Compromised credentials`). They arrive in the `Girs` column as a JSON
array of `{path, name}` objects:

```json
[{"path":"1.1.5","name":"Information-stealer malware"},
 {"path":"4.2.2","name":"Compromised credentials"},
 {"path":"4.4.1","name":"Phishing"},
 {"path":"5.2.6","name":"Credential access tactic"}]
```

### Extract the paths first

> ⚠️ **Never filter GIRs with `has`.** `has` does term matching over the column's text and treats `.` as a
> separator, so **`Girs has "1.1"` matches every row whose GIR path is `1.1.5`** - a silent over-match that
> will make an analytics rule fire on the wrong records. Verified against live data: `Girs has "1.1"` returned
> every row in the table, while the correct filter below returned none.

Pull the paths into an array of plain strings, then use `set_has_element`, which compares whole elements and
does no tokenisation:

```kusto
Intel471CredentialOccurrences_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs)),
         GirNames = extract_all(@'"name":"([^"]+)"', tostring(Girs))
```

`extract_all` is used rather than `mv-apply` because `mv-apply` **drops rows whose GIR array is empty**,
silently shrinking your result set.

### Filter by a single GIR ID

```kusto
Intel471CredentialOccurrences_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where set_has_element(GirPaths, "4.2.2")          // Compromised credentials
| project LastUpdatedTime, CredentialLogin, AccessedDomain, MalwareFamily
```

### Filter by several GIR IDs

Any of them:

```kusto
Intel471CredentialOccurrences_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where set_has_element(GirPaths, "1.1.5") or set_has_element(GirPaths, "4.4.1")
```

All of them, expressed as a set operation:

```kusto
let Required = dynamic(["1.1.5", "4.2.2"]);
Intel471CredentialOccurrences_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where array_length(set_intersect(GirPaths, Required)) == array_length(Required)
```

### Filter by GIR name instead of ID

```kusto
Intel471CredentialOccurrences_CL
| extend GirNames = extract_all(@'"name":"([^"]+)"', tostring(Girs))
| where set_has_element(GirNames, "Information-stealer malware")
```

### See which GIRs your data actually carries

Useful before writing a rule, so you filter on something that exists:

```kusto
Intel471CredentialOccurrences_CL
| mv-apply g = Girs on (
    project Path = tostring(g.path), Name = tostring(g.name)
  )
| summarize Occurrences = count(), Credentials = dcount(CredentialId) by Path, Name
| order by Occurrences desc
```

### Save it as a function

Rather than repeating the `extract_all` in every query, save it once as a workspace function
(**Logs** → run the query → **Save** → *Save as function*, name `Intel471Credentials`):

```kusto
Intel471CredentialOccurrences_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs)),
         GirNames = extract_all(@'"name":"([^"]+)"', tostring(Girs)),
         GirPathsDisplay = strcat_array(extract_all(@'"path":"([^"]+)"', tostring(Girs)), ", ")
```

Queries then read `Intel471Credentials | where set_has_element(GirPaths, "4.2.2")`, and GIRs render as
`1.1.5, 4.2.2, 4.4.1, 5.2.6` instead of raw JSON.

### Filter server-side instead

If you only ever care about certain GIRs, filtering at the API is cheaper than ingesting and discarding - it
reduces both volume and cost. Add `girs` to the `payload` variable, as described in
[Adding Verity API filters](#adding-verity-api-filters):

```json
{ "size": 100, "girs": "4.2.2,1.1.5" }
```

`my_girs` and `company_pirs` are accepted as aliases for the requirements configured on your account.
Remember that changing `payload` invalidates the stored cursor and triggers a bounded re-ingest.

## Table schema and data mapping

Data is fetched from the `/credentials/occurrences/stream` Verity endpoint. One API object becomes one row.
The API nests three levels deep; the table is flat.

**The `/credentials/occurrences/stream` endpoint is used rather than `/credentials/stream`** because only the
occurrence response carries the information stealer details as *scalars*. On `/credentials/stream` the same
fields come back as parallel arrays aggregated across sightings, with no way to tell which machine ran which
stealer at which time.

Transformations applied:

- **Dropped:** `data.credential.password.password_plain` (deliberately, see [Overview](#overview)).
  `count` and `cursor_next` are envelope fields, not per-record data.
- **Synthesised:** `TimeGenerated` (ingest time) and `SourceSystem` (`Intel 471 Verity`).
- **Derived:** `AccountName` and `AccountUPNSuffix`, split from `credential_login` on `@`, so analytics rules
  can map the Sentinel **Account** entity without repeating the split. A login that is not an email puts the
  whole value in `AccountName` and leaves the suffix empty.
- **Flattened and renamed:** everything else - snake_case to PascalCase, with abbreviations expanded
  (`os` → `OperatingSystem`, `ip` → `SourceIP`, `version` → `StealerVersion`).
- **Kept as JSON** (`dynamic`): `Affiliations`, `Girs` and `PasswordComplexity`. The per-character-class
  counts exist only inside `PasswordComplexity`; `length`, `entropy`, `score` and `weakness` are also promoted
  to typed scalar columns.
- **Values are otherwise untouched** - no rounding, casing, trimming or unit conversion. Every field is read
  defensively, so a missing nested object yields `null` rather than failing the run.

| Column | Type | Source field in the API response | Meaning |
| --- | --- | --- | --- |
| `TimeGenerated` | datetime | _(synthesised)_ `utcNow()` | Time this playbook ingested the row - NOT when the credential was seen. Use LastUpdatedTime for that. |
| `OccurrenceId` | string | `id` | Unique credential occurrence identifier. |
| `LastUpdatedTime` | datetime | `last_updated_ts` | Occurrence last modification date. The field the stream is ordered and cursored by. |
| `FirstSeenTime` | datetime | `activity.first_seen_ts` | Start of the credential activity range. |
| `LastSeenTime` | datetime | `activity.last_seen_ts` | End of the credential activity range. |
| `CredentialId` | string | `data.credential.id` | Unique credential identifier. Multiple occurrences share one credential. |
| `CredentialLogin` | string | `data.credential.credential_login` | Login of the credential, usually an email address. |
| `AccountName` | string | _(derived)_ from `data.credential.credential_login` | Derived: CredentialLogin before the @, for Sentinel Account entity mapping. |
| `AccountUPNSuffix` | string | _(derived)_ from `data.credential.credential_login` | Derived: CredentialLogin after the @. Empty when the login is not an email. |
| `CredentialDomain` | string | `data.credential.credential_domain` | Domain of the credential login. |
| `DetectionDomain` | string | `data.credential.detection_domain` | Monitored domain that caused this credential to be detected. |
| `Affiliations` | dynamic | `data.credential.affiliations` | Array of my_employees, vip_emails, my_customers, third_parties. |
| `PasswordId` | string | `data.credential.password.id` | Opaque password identifier. Equal ids mean equal passwords - useful for finding shared passwords. |
| `PasswordStrength` | string | `data.credential.password.strength` | excellent, strong, medium, weak, poor or not_provided. |
| `PasswordLength` | int | `data.credential.password.complexity.length` | Number of characters in the password. |
| `PasswordEntropy` | real | `data.credential.password.complexity.entropy` | Password entropy. |
| `PasswordScore` | real | `data.credential.password.complexity.score` | Password score, 0 to 1. |
| `PasswordWeakness` | real | `data.credential.password.complexity.weakness` | Password weakness. |
| `PasswordComplexity` | dynamic | `data.credential.password.complexity` | Full complexity object: per-character-class counts plus length, score, weakness, entropy. |
| `AccessedDomain` | string | `data.accessed_domain` | Domain the victim was logging in to when the credential was captured. |
| `AccessedUrl` | string | `data.accessed_url` | URL the victim was logging in to. |
| `CredentialSetId` | string | `data.credential_set.id` | Identifier of the credential set this sighting came from. |
| `CredentialSetName` | string | `data.credential_set.name` | Name of the credential set. |
| `CredentialType` | string | `data.credential_type` | Type of the credential set, e.g. infostealer. |
| `FilePath` | string | `data.file_path` | Path of the file within the credential set that held this occurrence. |
| `SoftwareName` | string | `data.software_name` | Application the credential was stolen from, e.g. Chrome (Profile 1). |
| `MalwareFamily` | string | `data.info_stealer.malware_family` | Information stealer family, e.g. Redline, Lumma, VIDAR. |
| `InfectionTime` | datetime | `data.info_stealer.infection_ts` | When the host was infected. |
| `MachineId` | string | `data.info_stealer.machine_id` | Identifier of the infected machine. |
| `PcName` | string | `data.info_stealer.pc_name` | Host name of the infected machine. |
| `ComputerUsername` | string | `data.info_stealer.computer_username` | Local user account on the infected machine. |
| `SourceIP` | string | `data.info_stealer.ip` | IP address of the infected machine. |
| `ISP` | string | `data.info_stealer.isp` | Internet service provider of the infected machine. |
| `OperatingSystem` | string | `data.info_stealer.os` | Operating system of the infected machine. |
| `AntivirusSoftware` | string | `data.info_stealer.antivirus_software` | Antivirus reported on the infected machine. |
| `MalwareInstallPath` | string | `data.info_stealer.malware_install_path` | Installation path of the stealer. |
| `ScreenshotPath` | string | `data.info_stealer.screenshot_path` | Path of the screenshot captured by the stealer. |
| `StealerVersion` | string | `data.info_stealer.version` | Version of the stealer. |
| `Girs` | dynamic | `classification.girs` | General Intelligence Requirements as an array of {path, name}. Do NOT filter with 'has' - see the README. |
| `SourceSystem` | string | _(literal)_ `Intel 471 Verity` | Provenance literal. |

### Fields the occurrence endpoint cannot provide

The API also defines `breach_ts`, `collected_ts` and `disclosure_ts` - the purported breach, collection and
disclosure dates - but those belong to the credential *set* object returned by the `/credential-sets`
endpoints. The occurrence response embeds only the set's `id` and `name`. If you need those dates, join on
`CredentialSetId` against data pulled separately from `/credential-sets/stream`.

## Volume and cost

Occurrences fan out: one credential seen in three credential sets produces three rows. In a sample pull, 100
rows covered only 49 distinct credentials across 13 logins. The table is billed per GB ingested, so plan for
it:

- Set **`affiliation_group`** in the `payload` variable - `my_employees` alone is usually a small fraction of
  the total. See [Adding Verity API filters](#adding-verity-api-filters).
- Set **`TableRetentionInDays`** rather than inheriting a long workspace default.
- Start with a small **`LookBackDays`**, confirm the daily rate, then backfill deliberately.
- If you only care about a subset of columns, the data collection rule's `transformKql` is the cheapest place
  to drop the rest - it runs before billing.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `403` at `PostToDcr`, message names the DCR immutable ID | The `Monitoring Metrics Publisher` grant is missing, or has not propagated. **Azure documents up to 30 minutes.** Verify the assignment's principal matches the logic app's `identity.principalId`, then wait. After a redeploy, check that both the identity and the DCR immutable ID are still the ones the grant refers to. |
| `413` at `PostToDcr` | The page exceeded the 1 MB Logs Ingestion limit. Lower `size` in the `payload` variable. |
| Run succeeds, `PostToDcr` returns `204`, but the table is empty | Normal for a few minutes - a first write to a new table has taken around 6 minutes in testing. Confirm the rows were accepted using the DCR's own metrics rather than KQL: `RowsReceived_Count` should match the page size and `RowsDropped_Count` should be absent. A non-zero `RowsDropped_Count` or `ColumnsDroppedCount` means a schema or type mismatch, which the `204` will not tell you. |
| Table looks empty but the metrics say rows were received | Check the query time range. The portal's time picker defaults to 24 hours and filters on `TimeGenerated`; a custom range keeps an absolute *end* time that can silently exclude new data. From the CLI, `az monitor log-analytics query` applies a default timespan - pass `--timespan P30D`. |
| `401` from the Verity API | Client ID and Client Secret are swapped, or the secret has been rotated. |
| `403` from the Verity API | The subscription may not include Credential Intelligence API access. Contact support@intel471.com. |
| Run terminates with `CursorBlobUnreadable` / `FromDateBlobUnreadable` | See [Storage account requirements](#storage-account-requirements). Immediately after deploying, this is the missing `Storage Blob Data Contributor` grant. |
| Run terminates with `CredentialUploadFailed` | A page failed to post. The cursor was not advanced, so the next run retries the same page. The message carries the HTTP status and response body. |
| `Intel471FilterSetChanged` in the run history | Expected after a filter change or an upgrade. The cursor was discarded and the from-date rewound by `MigrationMarginHours`; a one-off overlapping re-ingest follows. |
| The API returns 0 occurrences | Check that your monitored domains are registered with Intel 471, and that `LookBackDays` covers a period in which credentials were actually collected. `count` in the `HTTP` action's output is the total matching your filters, independent of `size`. |
| Duplicate-looking rows | Expected. Rows are sightings, and the API can emit duplicate occurrences. Deduplicate at query time - see [Two query traps](#two-query-traps). |
