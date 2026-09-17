# Intel 471 Credential Intelligence import to Sentinel

## Table of contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Getting your Intel 471 API credentials](#getting-your-intel-471-api-credentials)
4. [Choosing the source: credentials or occurrences](#choosing-the-source-credentials-or-occurrences)
    - [Which one for which job](#which-one-for-which-job)
    - [Do not run both](#do-not-run-both)
    - [Switching source later](#switching-source-later)
5. [What the template creates](#what-the-template-creates)
6. [Storage account requirements](#storage-account-requirements)
7. [Deployment instructions](#deployment-instructions)
8. [Post-deployment instructions](#post-deployment-instructions)
9. [Adding Verity API filters](#adding-verity-api-filters)
10. [How paging and the cursor work](#how-paging-and-the-cursor-work)
11. [Querying credential data in Sentinel](#querying-credential-data-in-sentinel)
    - [Grain-agnostic queries](#grain-agnostic-queries)
12. [Filtering by GIR](#filtering-by-gir)
13. [Table schema and data mapping](#table-schema-and-data-mapping)
14. [Volume and cost](#volume-and-cost)
15. [Troubleshooting](#troubleshooting)

## Overview

This playbook fetches compromised credentials from the Intel 471
[Verity 471 Credential Intelligence API](https://developer.intel471.com) and writes them into a custom Log
Analytics table, `Intel471Credentials_CL`, using the
[Azure Monitor Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview).

**Two sources are available**, selected with the `CredentialSource` dropdown at deployment:
**Credentials** (the default - one row per unique credential) or **Occurrences** (one row per sighting).
Both write to the same table, tagged with a `RecordType` column, so you can start with one and switch later
without rebuilding anything. See
[Choosing the source](#choosing-the-source-credentials-or-occurrences).

A row carries the login, the monitored domain that matched it, password strength and complexity metadata, the
credential sets it was found in, and - where the credential came from an information stealer rather than a
combination list - the malware family and the infected host that captured it.

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
- **Custom table** `Intel471Credentials_CL` in the Log Analytics workspace you nominate.
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

## Choosing the source: credentials or occurrences

The Verity Credential Intelligence API exposes the same underlying data at two grains, and the
`CredentialSource` parameter picks which one this playbook pulls.

| | **Credentials** (default) | **Occurrences** |
| --- | --- | --- |
| Endpoint | `/credentials/stream` | `/credentials/occurrences/stream` |
| A row is | one **unique credential** - login + password + accessed domain | one **sighting** of a credential in one credential set |
| `RecordType` | `credential` | `occurrence` |
| Volume | baseline | roughly 1.6x higher |
| Infostealer detail | **aggregated** across every sighting | **correlated** - one machine, one stealer, one IP, one timestamp per row |
| Only here | `AccessedDomainsCount` | `OccurrenceId`, `FilePath`, `SoftwareName`, `CredentialSetId`, `CredentialSetName`, `InfectionTime` |

**Pick Credentials when the question is "which of our accounts are exposed?"** It is the smaller, cheaper
feed and the natural grain for alerting on employee exposure, password-policy reporting and password reuse.

**Pick Occurrences when the question is "which of our hosts is infected, and with what?"** It is the only
source that keeps the infostealer fields correlated on one row. On the credentials endpoint those fields come
back as *parallel arrays* aggregated across sightings, so a credential captured by two different stealers on
two different machines gives you `["Lumma","Redline"]` and `["machine-a","machine-b"]` with nothing tying
them together. The playbook flattens those arrays into comma-separated strings, which is exact for the
overwhelming majority of credentials - most have a single malware family and a single machine - and the
untouched original is always available in the `InfoStealer` column.

### Which one for which job

Pick **one**. If your work spans both columns below, pick Occurrences - it answers everything Credentials
answers, as explained in [Do not run both](#do-not-run-both).

| What you are trying to do | Source | Why |
| --- | --- | --- |
| **Match exposed logins against your directory** - join to `SigninLogs`, Entra ID, your IdP or an HR list to find which of *your* accounts appear | **Credentials** | Identity matching only needs the login, and one row per credential is exactly one identity to match. Occurrences would hand you the same login three times and you would deduplicate it straight back. |
| Alert when an employee credential appears | **Credentials** | One alert per exposed credential. On occurrences the same exposure fires once per credential set. |
| Drive a password-reset campaign | **Credentials** | The deliverable is a list of accounts, not sightings. |
| Password-policy reporting - strength, length, entropy distribution | **Credentials** | Password metadata is identical on both grains, so the cheaper one wins. |
| Find shared or reused passwords across accounts | **Credentials** | `PasswordId` is per credential; counting it over occurrences inflates every group. |
| Third-party / supplier exposure reporting | **Credentials** | Counting exposed accounts per vendor domain. |
| **Infostealer forensics** - which machine was infected, by which stealer, from which IP, at what time | **Occurrences** | The only grain where those fields are correlated on one row. On credential rows they are aggregated and comma-joined. |
| Scope an incident around one infected host | **Occurrences** | Needs `MachineId` tied to `InfectionTime`, `SourceIP` and `PcName` per sighting. |
| Work out where a credential leaked from | **Occurrences** | `FilePath` and `SoftwareName` (e.g. `Chrome (Profile 1)`) exist only here. |
| Track which credential set a sighting came from | **Occurrences** | `CredentialSetId` / `CredentialSetName` are scalar per row; credential rows can span several sets. |
| Measure exposure over time per credential set | **Occurrences** | One row per (credential, set) pair is the natural fact table. |

The short version: **Credentials is an identity list, Occurrences is an event log.** If the output of your
query is a set of accounts, use Credentials. If it is a set of infections, use Occurrences.

### Do not run both

Deploying the template twice, once per source, is technically possible and almost always a mistake.
**Occurrences is a near-superset of Credentials**: occurrence rows populate 43 of the 44 columns, credential
rows populate 38. The only thing on a credential row and not on an occurrence row is `AccessedDomainsCount`,
a convenience statistic.

In particular, every field identity matching needs - `CredentialLogin`, `AccountName`, `AccountUPNSuffix`,
`CredentialDomain`, `DetectionDomain`, `Affiliations`, `PasswordId`, all the password metadata - is present
on occurrence rows. They are simply repeated once per sighting. So if you need forensics *and* identity
matching, ingest **Occurrences only** and collapse to one row per credential when you want the identity view:

```kusto
Intel471Credentials_CL
| where RecordType == "occurrence"
| summarize arg_max(LastUpdatedTime, *) by CredentialId
```

That gives you the credential grain from occurrence data, and the credential-grain aggregates too:

```kusto
Intel471Credentials_CL
| where RecordType == "occurrence"
| summarize Sightings       = count(),
            AccessedDomains = dcount(AccessedDomain),
            Families        = make_set(MalwareFamily),
            Machines        = make_set(MachineId),
            Sets            = make_set(CredentialSetName),
            LastUpdatedTime = max(LastUpdatedTime)
    by CredentialId, CredentialLogin
```

Running both feeds instead costs roughly 2.6x a credentials-only deployment, stores every exposure twice,
forces a `RecordType` filter into every query, and buys you one statistic column. **So the choice is about
cost and query simplicity, not capability:** take Credentials when the identity view is all you will ever
need and you want the cheaper, pre-deduplicated feed; take Occurrences when you need per-sighting detail at
all, knowing it still answers every identity question.

### Switching source later

Redeploy with the other value. Three things make this safe:

- **The table is shared and its schema is a union of both**, so nothing needs rebuilding. Rows are
  distinguishable by `RecordType`, and `CredentialId` is populated for both, so credential rows join to
  occurrence rows.
- **Each source keeps its own cursor.** A Verity cursor is only valid for the endpoint that issued it, so the
  two use separate blobs and switching does not corrupt or lose your position in the other. Switching back
  later resumes where that source left off.
- **A source you switch away from simply stops producing rows.** Existing rows stay.

The one thing to be aware of: after switching, a query that does not filter on `RecordType` sees both grains
at once and will double-count. See [Querying credential data in Sentinel](#querying-credential-data-in-sentinel).

## What the template creates

| Resource | Name | Purpose |
| --- | --- | --- |
| Custom table | `Intel471Credentials_CL` | Where the data lands. Its 44-column schema is the union of both sources. Created in the workspace's resource group via a nested deployment, so the workspace may live in a different resource group from the playbook. |
| Data collection endpoint | `dce-intel471-creds` | The HTTPS address the logic app posts to. |
| Data collection rule | `dcr-intel471-creds` | Declares the incoming stream `Custom-Intel471Credentials_CL`, its 40 typed columns, and the workspace destination. Passes data through unchanged (`transformKql: "source"`). |
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

Each source keeps its own pair, because a Verity cursor is only valid for the endpoint that issued it:

| `CredentialSource` | Cursor blob | From-date blob |
| --- | --- | --- |
| `Credentials` | `cursorCredentialsVerity.txt` | `fromdateCredentialsVerity.txt` |
| `Occurrences` | `cursorCredentialOccurrencesVerity.txt` | `fromdateCredentialOccurrencesVerity.txt` |

The cursor blob holds `<filter set>|<cursor>` and is rewritten after every successfully posted page; the
from-date blob is written on first run and again whenever the filter set changes.

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
    * **CredentialSource**: `Credentials` (default) or `Occurrences`. Hover the info icon on the deployment
      form for the full explanation, or see
      [Choosing the source](#choosing-the-source-credentials-or-occurrences). Both write the same table and
      the choice can be changed later by redeploying.
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
6. `CollectAndSubmitCredentials` pages the stream until it drains: `HTTP` → `Parse_JSON` → `SetHasResults` →
   `SourceIsOccurrences` (which runs `MapOccurrences` or `MapCredentials` depending on the source) →
   `PostToDcr` → **then** `StoreCursor`.
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

> ⚠️ **If the table holds both record types, always filter on `RecordType`.** A credential row and the
> occurrence rows that produced it describe the same exposure at different grains, so a query spanning both
> double-counts. Check what you have with:
>
> ```kusto
> Intel471Credentials_CL | summarize Rows = count(), Credentials = dcount(CredentialId) by RecordType
> ```

First 20 rows:

```kusto
Intel471Credentials_CL | take 20
```

Employee credentials learned about in the last day, with detection latency. Works on either grain - add a
`RecordType` filter if the table holds both:

```kusto
Intel471Credentials_CL
| where TimeGenerated > ago(1d) and Affiliations has "my_employees"
| extend DetectionLatency = TimeGenerated - LastUpdatedTime
| project RecordType, LastUpdatedTime, DetectionLatency, CredentialLogin, AccessedDomain, MalwareFamily, PasswordStrength
| order by LastUpdatedTime desc
```

Infostealer-infected hosts, grouped by machine. **Occurrence rows only** - on credential rows `MachineId`
may hold several machines joined with commas, which would corrupt the grouping:

```kusto
Intel471Credentials_CL
| where RecordType == "occurrence" and isnotempty(MachineId)
| summarize Credentials = dcount(CredentialId), Logins = make_set(CredentialLogin, 10),
            FirstSeen = min(FirstSeenTime), LastSeen = max(LastSeenTime)
    by MachineId, PcName, ComputerUsername, MalwareFamily, SourceIP, OperatingSystem
| order by Credentials desc
```

Credentials that fail your password policy. Collapsing to one row per `CredentialId` makes this correct on
either grain:

```kusto
Intel471Credentials_CL
| where PasswordStrength in ("poor", "weak") or PasswordLength < 12
| summarize arg_max(LastUpdatedTime, *) by CredentialId
| project LastUpdatedTime, CredentialLogin, PasswordStrength, PasswordLength, PasswordEntropy
```

Which credential sets a credential turned up in - `CredentialSets` is populated on both grains, as a
single-element array for occurrence rows:

```kusto
Intel471Credentials_CL
| mv-apply cs = CredentialSets on ( project SetName = tostring(cs.name) )
| summarize Sets = make_set(SetName) by CredentialLogin, CredentialId
| where array_length(Sets) > 1
```

Shared passwords - credential-stuffing candidates:

```kusto
Intel471Credentials_CL
| where isnotempty(PasswordId)
| summarize Accounts = dcount(CredentialLogin), Logins = make_set(CredentialLogin, 20) by PasswordId
| where Accounts > 1
| order by Accounts desc
```

Join against Entra ID sign-ins to see whether an exposed credential was actually used:

```kusto
Intel471Credentials_CL
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

### Grain-agnostic queries

Of the 44 columns, **23 mean exactly the same thing on both grains** and can be queried without any care:

`CredentialId`, `CredentialLogin`, `AccountName`, `AccountUPNSuffix`, `CredentialDomain`, `DetectionDomain`,
`Affiliations`, `AccessedDomain`, `AccessedUrl`, `PasswordId`, `PasswordStrength`, `PasswordLength`,
`PasswordEntropy`, `PasswordScore`, `PasswordWeakness`, `PasswordComplexity`, `Girs`, `LastUpdatedTime`,
`FirstSeenTime`, `LastSeenTime`, `TimeGenerated`, `RecordType`, `SourceSystem`.

Seven are populated on one grain only - `OccurrenceId`, `CredentialSetId`, `CredentialSetName`, `FilePath`,
`SoftwareName`, `InfectionTime` (occurrence) and `AccessedDomainsCount` (credential). The remaining 14 exist
on both but change shape: the infostealer columns are a single value on occurrence rows and a comma-joined
list on credential rows, and `CredentialSets` / `CredentialTypes` are arrays with one element on occurrence
rows and several on credential rows.

Two rules make a query correct on either grain, or on a table holding both:

**1. Count credentials, not rows.** `count()` answers a different question per grain. `dcount(CredentialId)`
answers the same one. When the number matters, `summarize by CredentialId | count` is exact where `dcount` is
an estimate.

**2. Normalise the joined columns with `split`.** A comma-joined list and a single value both become an
array, so one filter works on both:

```kusto
let Creds =
    Intel471Credentials_CL
    | extend MalwareFamilies = iff(isempty(MalwareFamily), dynamic([]), split(MalwareFamily, ", ")),
             MachineIds      = iff(isempty(MachineId),     dynamic([]), split(MachineId, ", ")),
             SourceIPs       = iff(isempty(SourceIP),      dynamic([]), split(SourceIP, ", ")),
             GirPaths        = extract_all(@'"path":"([^"]+)"', tostring(Girs));
Creds
| summarize Credentials  = dcount(CredentialId),
            Redline      = dcountif(CredentialId, set_has_element(MalwareFamilies, "Redline")),
            WeakPasswords= dcountif(CredentialId, PasswordStrength in ("poor", "weak")),
            Employees    = dcountif(CredentialId, Affiliations has "my_employees")
    by RecordType
```

Run that against either source and the per-credential numbers are identical; only the row count differs.
Save the `let` block as a workspace function and every downstream query inherits it.

**When you cannot be grain-agnostic:** anything that needs one machine tied to one stealer at one moment -
host hunting, infection timelines, `FilePath` and `SoftwareName` forensics. That correlation only exists on
occurrence rows, which is the whole reason the source is selectable. Such queries should say
`| where RecordType == "occurrence"` explicitly rather than silently return nothing useful.

### Three query traps

**Deduplicate before counting.** On the occurrences grain the API can return several sightings of the same
credential, sometimes with identical content and different `OccurrenceId`s - a known upstream issue - and
at-least-once retry can re-ship a page. Re-ingesting the same window after a filter change also produces one
row per ingest. Collapse to one row per credential:

```kusto
Intel471Credentials_CL
| where RecordType == "occurrence"
| summarize arg_max(LastUpdatedTime, *) by CredentialId, CredentialSetId, AccessedDomain
```

Or, for a count that is correct no matter which grains are present:

```kusto
Intel471Credentials_CL | summarize UniqueCredentials = dcount(CredentialId)
```

Note `dcount` is an estimate; `summarize by CredentialId | count` is exact and worth using when the number
matters.

**Never filter GIRs with `has`** - see [Filtering by GIR](#filtering-by-gir) for why, and what to do instead.

**`InfoStealer` is almost never null, even when there is no stealer data.** The API returns an
`info_stealer` object on essentially every record, populated or not, so `isnotnull(InfoStealer)` matches
nearly everything and is useless as a "was this captured by a stealer?" test. Credentials harvested from
combination lists - `CredentialTypes` containing `regex` rather than `infostealer` - carry an empty object
with every field blank.

Test a field you actually need instead:

```kusto
// wrong - matches combination-list credentials too
Intel471Credentials_CL | where isnotnull(InfoStealer)

// right - pick the field the query depends on
Intel471Credentials_CL | where isnotempty(MachineId)        // host hunting
Intel471Credentials_CL | where isnotempty(MalwareFamily)    // stealer attribution
```

Or split the population explicitly, which is also the quickest way to see whether a window contains any
stealer data at all before concluding a query is broken:

```kusto
Intel471Credentials_CL
| summarize Rows = count(),
            WithStealer = countif(isnotempty(MalwareFamily) or isnotempty(MachineId))
    by RecordType, Types = tostring(CredentialTypes)
```

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
Intel471Credentials_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs)),
         GirNames = extract_all(@'"name":"([^"]+)"', tostring(Girs))
```

`extract_all` is used rather than `mv-apply` because `mv-apply` **drops rows whose GIR array is empty**,
silently shrinking your result set.

### Filter by a single GIR ID

```kusto
Intel471Credentials_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where set_has_element(GirPaths, "4.2.2")          // Compromised credentials
| project LastUpdatedTime, CredentialLogin, AccessedDomain, MalwareFamily
```

### Filter by several GIR IDs

Any of them:

```kusto
Intel471Credentials_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where set_has_element(GirPaths, "1.1.5") or set_has_element(GirPaths, "4.4.1")
```

All of them, expressed as a set operation:

```kusto
let Required = dynamic(["1.1.5", "4.2.2"]);
Intel471Credentials_CL
| extend GirPaths = extract_all(@'"path":"([^"]+)"', tostring(Girs))
| where array_length(set_intersect(GirPaths, Required)) == array_length(Required)
```

### Filter by GIR name instead of ID

```kusto
Intel471Credentials_CL
| extend GirNames = extract_all(@'"name":"([^"]+)"', tostring(Girs))
| where set_has_element(GirNames, "Information-stealer malware")
```

### See which GIRs your data actually carries

Useful before writing a rule, so you filter on something that exists:

```kusto
Intel471Credentials_CL
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
Intel471Credentials_CL
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

One API object becomes one row. The API nests three levels deep; the table is flat. The schema is the
**union of both sources**, so a column may be populated on one grain and empty on the other - the two
right-hand columns below say which.

The two responses differ structurally, so the playbook carries two mappings and picks one at run time in the
`SourceIsOccurrences` action. The differences worth knowing:

| | Credentials | Occurrences |
| --- | --- | --- |
| Top-level `id` | the credential | the sighting |
| Login, domain, affiliations, password | `data.*` | `data.credential.*` |
| Credential set | `data.credential_sets` (array) | `data.credential_set` (single) |
| Credential type | `data.credential_set_type` (array) | `data.credential_type` (single) |
| `data.info_stealer` fields | arrays | scalars |

Transformations applied:

- **Dropped:** `password_plain` (deliberately, see [Overview](#overview)). `count` and `cursor_next` are
  envelope fields, not per-record data.
- **Synthesised:** `TimeGenerated` (ingest time), `RecordType` (which source produced the row) and
  `SourceSystem` (`Intel 471 Verity`).
- **Array-collapsed on credential rows:** the `info_stealer` string arrays are joined with `", "` into the
  scalar columns. Exact for the overwhelming majority of credentials, which have a single value, readable for
  the rest, and the untouched original is always in the `InfoStealer` column. `infection_ts` is *not* collapsed - a joined
  datetime would be meaningless, so `InfectionTime` is empty on credential rows.
- **Array-normalised on occurrence rows:** `credential_set` and `credential_type` are wrapped into
  single-element arrays so `CredentialSets` and `CredentialTypes` have the same shape on both grains.
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

| Column | Type | Credential rows | Occurrence rows | Meaning |
| --- | --- | --- | --- | --- |
| `TimeGenerated` | datetime | `utcNow()` | `utcNow()` | Time this playbook ingested the row - NOT when the credential was seen. Use LastUpdatedTime for that. |
| `RecordType` | string | `credential` | `occurrence` | Which endpoint produced this row: 'occurrence' (one sighting) or 'credential' (one unique credential, aggregated across its sightings). Always filter or group by this when a table holds both. |
| `CredentialId` | string | `id` | `data.credential.id` | Unique credential identifier. Stable across both record types, so it joins credential rows to occurrence rows. |
| `OccurrenceId` | string | — | `id` | Unique sighting identifier. Populated only when RecordType is 'occurrence'. |
| `LastUpdatedTime` | datetime | `last_updated_ts` | `last_updated_ts` | Record last modification date. The field the stream is ordered and cursored by. |
| `FirstSeenTime` | datetime | `activity.first_seen_ts` | `activity.first_seen_ts` | Start of the credential activity range. |
| `LastSeenTime` | datetime | `activity.last_seen_ts` | `activity.last_seen_ts` | End of the credential activity range. |
| `CredentialLogin` | string | `data.credential_login` | `data.credential.credential_login` | Login of the credential, usually an email address. |
| `AccountName` | string | derived from login | derived from login | Derived: CredentialLogin before the @, for Sentinel Account entity mapping. |
| `AccountUPNSuffix` | string | derived from login | derived from login | Derived: CredentialLogin after the @. Empty when the login is not an email. |
| `CredentialDomain` | string | `data.credential_domain` | `data.credential.credential_domain` | Domain of the credential login. |
| `DetectionDomain` | string | `data.detection_domain` | `data.credential.detection_domain` | Monitored domain that caused this credential to be detected. |
| `Affiliations` | dynamic | `data.affiliations` | `data.credential.affiliations` | Array of my_employees, vip_emails, my_customers, third_parties. |
| `PasswordId` | string | `data.password.id` | `data.credential.password.id` | Opaque password identifier. Equal ids mean equal passwords - use it to find shared passwords. |
| `PasswordStrength` | string | `data.password.strength` | `data.credential.password.strength` | excellent, strong, medium, weak, poor or not_provided. |
| `PasswordLength` | int | `data.password.complexity.length` | `data.credential.password.complexity.length` | Number of characters in the password. |
| `PasswordEntropy` | real | `data.password.complexity.entropy` | `data.credential.password.complexity.entropy` | Password entropy. |
| `PasswordScore` | real | `data.password.complexity.score` | `data.credential.password.complexity.score` | Password score, 0 to 1. |
| `PasswordWeakness` | real | `data.password.complexity.weakness` | `data.credential.password.complexity.weakness` | Password weakness. |
| `PasswordComplexity` | dynamic | `data.password.complexity` | `data.credential.password.complexity` | Full complexity object: per-character-class counts plus length, score, weakness, entropy. |
| `AccessedDomain` | string | `data.accessed_domain` | `data.accessed_domain` | Domain the victim was logging in to when the credential was captured. |
| `AccessedUrl` | string | `data.accessed_url` | `data.accessed_url` | URL the victim was logging in to. Deprecated on the credentials endpoint, where it mirrors AccessedDomain. |
| `CredentialSets` | dynamic | `data.credential_sets` | `data.credential_set` (wrapped) | Every credential set this record belongs to, as an array of {id, name}. Populated for both record types - a single-element array for occurrences. A credential can belong to several sets. |
| `CredentialSetId` | string | — | `data.credential_set.id` | Identifier of the single credential set this sighting came from. Occurrence rows only; credential rows can belong to several, see CredentialSets. |
| `CredentialSetName` | string | — | `data.credential_set.name` | Name of the credential set. Occurrence rows only, see CredentialSets. |
| `CredentialTypes` | dynamic | `data.credential_set_type` | `data.credential_type` (wrapped) | Types of the credential sets involved, e.g. infostealer. Array for both record types. |
| `FilePath` | string | — | `data.file_path` | Path of the file within the credential set that held this sighting. Occurrence rows only. |
| `SoftwareName` | string | — | `data.software_name` | Application the credential was stolen from, e.g. Chrome (Profile 1). Occurrence rows only. |
| `AccessedDomainsCount` | int | `statistics.accessed_domains_count` | — | Number of distinct accessed domains for this credential. Credential rows only. |
| `MalwareFamily` | string | `data.info_stealer.malware_family` (joined) | `data.info_stealer.malware_family` | Information stealer family, e.g. Redline, Lumma, VIDAR. On credential rows this aggregates every family that captured the credential, comma separated - usually a single value. |
| `InfectionTime` | datetime | — | `data.info_stealer.infection_ts` | When the host was infected. Occurrence rows only - credential rows aggregate several, see the InfoStealer column. |
| `MachineId` | string | `data.info_stealer.machine_id` (joined) | `data.info_stealer.machine_id` | Identifier of the infected machine. Comma separated on credential rows. |
| `PcName` | string | `data.info_stealer.pc_name` (joined) | `data.info_stealer.pc_name` | Host name of the infected machine. Comma separated on credential rows. |
| `ComputerUsername` | string | `data.info_stealer.computer_username` (joined) | `data.info_stealer.computer_username` | Local user account on the infected machine. Comma separated on credential rows. |
| `SourceIP` | string | `data.info_stealer.ip` (joined) | `data.info_stealer.ip` | IP address of the infected machine. Comma separated on credential rows. |
| `ISP` | string | `data.info_stealer.isp` (joined) | `data.info_stealer.isp` | Internet service provider of the infected machine. Comma separated on credential rows. |
| `OperatingSystem` | string | `data.info_stealer.os` (joined) | `data.info_stealer.os` | Operating system of the infected machine. Comma separated on credential rows. |
| `AntivirusSoftware` | string | `data.info_stealer.antivirus_software` (joined) | `data.info_stealer.antivirus_software` | Antivirus reported on the infected machine. Comma separated on credential rows. |
| `MalwareInstallPath` | string | `data.info_stealer.malware_install_path` (joined) | `data.info_stealer.malware_install_path` | Installation path of the stealer. Comma separated on credential rows. |
| `ScreenshotPath` | string | `data.info_stealer.screenshot_path` (joined) | `data.info_stealer.screenshot_path` | Path of the screenshot captured by the stealer. Comma separated on credential rows. |
| `StealerVersion` | string | `data.info_stealer.version` (joined) | `data.info_stealer.version` | Version of the stealer. Comma separated on credential rows. |
| `InfoStealer` | dynamic | `data.info_stealer` | `data.info_stealer` | The raw info_stealer object exactly as the API returned it - scalars on occurrence rows, parallel arrays on credential rows. Lossless escape hatch for anything the flattened columns above cannot express. |
| `Girs` | dynamic | `classification.girs` | `classification.girs` | General Intelligence Requirements as an array of {path, name}. Do NOT filter with 'has' - see the README. |
| `SourceSystem` | string | `Intel 471 Verity` | `Intel 471 Verity` | Provenance literal. |

### Fields neither endpoint can provide

The API also defines `breach_ts`, `collected_ts` and `disclosure_ts` - the purported breach, collection and
disclosure dates - but those belong to the credential *set* object returned by the `/credential-sets`
endpoints. Both credential and occurrence responses embed only the set's `id` and `name`. If you need those
dates, join on `CredentialSetId` (occurrence rows) or `CredentialSets` (either grain) against data pulled
separately from `/credential-sets/stream`.

## Volume and cost

The table is billed per GB ingested, so plan for it:

- **Choose the right source.** `Credentials` is the cheaper grain and the default. Occurrences fan out - one
  credential seen in three credential sets produces three rows - so expect roughly 1.6x the rows for the same
  exposure. Only pay that if you need the correlated infostealer detail.

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
| Duplicate-looking rows | Expected on the occurrences grain - rows are sightings, and the API can emit duplicate occurrences. Also expected if the table holds both grains, or after a filter change re-ingested a window. Deduplicate at query time - see [Three query traps](#three-query-traps). |
| Counts look roughly doubled | The table probably holds both record types after a source switch. Filter on `RecordType`, or count with `dcount(CredentialId)`. |
| Host-hunting queries return nothing | The window may contain only combination-list credentials, which have no stealer data. Check with `summarize countif(isnotempty(MalwareFamily)) by tostring(CredentialTypes)` - `regex` means harvested from a list, `infostealer` means captured by malware. Note `isnotnull(InfoStealer)` does **not** distinguish them; the object is present but empty. |
| A column is unexpectedly empty | Check the two right-hand columns of the schema table - several are populated on only one grain. `OccurrenceId`, `FilePath`, `SoftwareName`, `CredentialSetId`, `CredentialSetName` and `InfectionTime` are occurrence-only; `AccessedDomainsCount` is credential-only. |
| Switched source but the new rows never arrive | Each source has its own cursor and from-date blob, so the new source bootstraps from `LookBackDays`. If that is 0 it starts from now and will only pick up newly updated records. |
