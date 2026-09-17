# Intel 471 solution — release checklist

Internal notes for cutting a new version of this solution. Each item exists because it has
bitten us at least once.

## 1. Before repackaging

- [ ] **Bump the `User-Agent` in both playbooks.** The packaging tool copies the header literal
      from `azuredeploy.json` verbatim — nothing injects the solution version — so a stale value
      ships silently. Both playbooks must carry
      `Intel471-SentinelMalwareIntelligence/<version>` and
      `Intel471-SentinelCredentialIntelligence/<version>`, matching the solution version. Verify with
      the `grep` in section 3 — it must print exactly two lines, both on the current version.
- [ ] **Bump `hidden-SentinelTemplateVersion`** on the `Microsoft.Logic/workflows` resource of
      every playbook whose content changed. The packaging tool reads the playbook template
      version from this tag and defaults to `1.0` when it is missing. If the tag does not move,
      the content hub cannot tell that the playbook template changed, existing installations
      never receive the update, and customers have to uninstall the solution first.
- [ ] **Add a `ReleaseNotes.md` entry.** Mandatory for marketplace certification. State the new
      playbook template versions alongside the solution version, in customer-facing language.
- [ ] **Validate every hunting query YAML before packaging.** The packaging tool stops at the
      first unparseable file and still writes a package, silently, so a single bad file ships a
      solution with only the queries that preceded it alphabetically:

      ```bash
      pwsh -NoProfile -Command 'foreach ($f in Get-ChildItem "Solutions/Intel471/Hunting Queries/*.yaml") {
        try { $null = ConvertFrom-Yaml (Get-Content -Raw $f.FullName) -ErrorAction Stop }
        catch { Write-Host "INVALID:" $f.Name } }'
      ```

      The usual cause is indentation inside the `query: |` block: a line at column 0 ends the
      block scalar, and everything after it is parsed as top-level YAML. Any continuation line
      must stay indented, even when editing only the KQL.
- [ ] **Hunting query IDs must be globally unique.** Content hub keys hunting queries on their
      `id`, so a GUID reused from another solution collides for any customer with both
      installed. Never copy a query from another solution without reissuing its GUID.

## 1a. The shared pull-loop skeleton

`Intel471-ImportMalwareIntelligenceToSentinel` and `Intel471-ImportCredentialIntelToSentinel` share their
pull loop. ARM has no include mechanism that survives Content Hub packaging, so the skeleton is **duplicated
on purpose** and kept diffable by using identical action and workflow-parameter names. These actions are
byte-identical between the two templates and a fix to one must be applied to the other:

`GetUsername`, `GetApiKey`, `ComputeFilterSetMarker`, `GetCursorFromBlob`, `IfCursorBlobExists`
(`SetCursorRaw`, `SetCursor`, `IfCursorBlobMissing`, `CreateBlobForCursor`,
`TerminateOnCursorBlobFailure`), `GetFromDateFromBlob`, `IfFromDateBlobExists` (`SetFromDateFromBlob`,
`IfFromDateBlobMissing`, `SetFromDate`, `CreateBlobForFromDate`, `TerminateOnFromDateBlobFailure`),
`IfFilterSetChanged` and all of its children, `HTTP` (bar the `User-Agent`), `CursorNotNull`,
`UpdateCursor`, `StoreCursor`, `IfUploadFailed`.

`InitVariables` differs only in that the credentials playbook has no `collectedIndicators` variable, and
`IfUploadFailed` differs only in its `runError`. Verify with:

```bash
python3 - <<'EOF'
import json
def acts(p):
    d=json.load(open(p)); w=[r for r in d["resources"] if r["type"]=="Microsoft.Logic/workflows"][0]
    return w["properties"]["definition"]["actions"]
a=acts("Solutions/Intel471/Playbooks/Intel471-ImportMalwareIntelligenceToSentinel/azuredeploy.json")
b=acts("Solutions/Intel471/Playbooks/Intel471-ImportCredentialIntelToSentinel/azuredeploy.json")
for n in ["GetUsername","GetApiKey","ComputeFilterSetMarker","GetCursorFromBlob","IfCursorBlobExists",
          "GetFromDateFromBlob","IfFromDateBlobExists","IfFilterSetChanged"]:
    assert json.dumps(a[n],sort_keys=True)==json.dumps(b[n],sort_keys=True), n
print("shared skeleton identical")
EOF
```

The feed-specific actions are deliberately named differently, because a credentials playbook whose actions
say "Indicators" is a documentation problem: the loop is `CollectAndSubmitCredentials`, the mappings are
`MapOccurrences` / `MapCredentials` behind a `SourceIsOccurrences` branch (mirroring the malware playbook's
`BackendIsVerity`), and the sink is `PostToDcr` rather than the Sentinel STIX upload.

## 1b. Credentials playbook specifics

- [ ] **The custom table, DCE and DCR live inside the playbook template.** No other playbook in this
      repository does that - every other DCR in `Azure-Sentinel` sits under `Data Connectors/`. After
      repackaging, confirm they survived:

      ```bash
      grep -c 'dataCollectionRules\|dataCollectionEndpoints' Solutions/Intel471/Package/mainTemplate.json
      ```

      The packaging tool passes unknown resource types through unconditionally
      (`common/commonFunctions.ps1:1486-1491`), so this should be non-zero. `az deployment group validate`
      does **not** descend into inline nested templates; `what-if` does, but silently omits a broken nested
      resource rather than erroring, so check for *presence* of the table:

      ```bash
      az deployment group what-if -g <rg> --template-file <playbook>/azuredeploy.json --parameters ... \
        --no-pretty-print --query "changes[?contains(resourceId,'tables')].changeType" -o tsv
      ```

- [ ] **Never add a plaintext password column.** `password_plain` is deliberately unmapped; Log Analytics has
      no column-level RBAC.
- [ ] **Keep the table, the DCR stream declaration and BOTH mappings in lockstep.** All four carry the same
      44 columns, in the same order, and a mismatch is rejected at ingest with a `204` and a silent row drop.
      The schema is the union of the two sources, so a column may be populated by only one mapping - but it
      must still be present in both. Verify with:

      ```bash
      python3 - <<'EOF'
      import json
      d=json.load(open("Solutions/Intel471/Playbooks/Intel471-ImportCredentialIntelToSentinel/azuredeploy.json"))
      nest=[r for r in d["resources"] if r["type"]=="Microsoft.Resources/deployments"][0]
      tbl=[c["name"] for c in nest["properties"]["template"]["resources"][0]["properties"]["schema"]["columns"]]
      dcr=[r for r in d["resources"] if r["type"].endswith("dataCollectionRules")][0]
      strm=[c["name"] for c in list(dcr["properties"]["streamDeclarations"].values())[0]["columns"]]
      w=[r for r in d["resources"] if r["type"]=="Microsoft.Logic/workflows"][0]
      br=w["properties"]["definition"]["actions"]["CollectAndSubmitCredentials"]["actions"]["SourceIsOccurrences"]
      occ=list(br["actions"]["MapOccurrences"]["inputs"]["select"])
      cre=list(br["else"]["actions"]["MapCredentials"]["inputs"]["select"])
      assert tbl==strm==occ==cre, "schema drift"
      print(f"{len(tbl)} columns aligned across table, stream and both mappings")
      EOF
      ```

## 2. Repackage with the V3 tool

```bash
pwsh Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV3.ps1 \
  -SolutionDataFolderPath <repo>/Solutions/Intel471/Data \
  -VersionMode local -VersionBump patch
```

- `-VersionMode local` **always increments** the version in `Data/Solution_Intel471.json` and
  writes the result back. To land on a specific version, seed the data file with the *previous*
  one. `-VersionMode catalog` derives the version from the published catalog entry instead, which
  is wrong whenever the catalog is behind (see section 5).
- The package filename must equal the version, e.g. `3.0.1` → `Package/3.0.1.zip`.
- The version must match across Partner Center, `Data/Solution_Intel471.json` and
  `Package/mainTemplate.json`.
- Delete the zip of any version that was built but never published, so the folder does not
  advertise a version that does not exist.
- **Re-apply the `learn.microsoft.com` hunting URI in `Package/createUiDefinition.json` after
  every packaging run.** The tool hardcodes `https://docs.microsoft.com/azure/sentinel/hunting`
  (`Tools/Create-Azure-Sentinel-Solution/common/commonFunctions.ps1`), so regeneration reverts the
  fix each time. After patching the file, rebuild the zip so the two agree:
  `zip -X -j <version>.zip createUiDefinition.json mainTemplate.json`.

## 3. Validate

```bash
# the zip must match the loose files it was built from
python3 -c "import zipfile,hashlib,io;z=zipfile.ZipFile('Package/<version>.zip');[print(n, hashlib.sha256(z.read(n)).hexdigest()==hashlib.sha256(io.open('Package/'+n,'rb').read()).hexdigest()) for n in z.namelist()]"

# the content counts must match what the solution actually ships
python3 -c "import json;from collections import Counter;d=json.load(open('Package/mainTemplate.json'));print(Counter(r['properties'].get('contentKind') for r in d['resources']))"

# UA and solution version must agree
grep -rho '"User-Agent": "[^"]*"' Playbooks/*/azuredeploy.json Package/mainTemplate.json | sort -u
grep -o '"_solutionVersion": "[^"]*"' Package/mainTemplate.json
```

- **arm-ttk:** one known failure, `IDs Should Be Derived From ResourceIDs`, is expected. It is a
  false positive on the `contentProductId` / `id` properties that the V3 tool generates for every
  Sentinel solution, and the already-certified packages fail it identically. Any *other* failure
  is real.
- The zip submitted for certification must match the repository contents exactly, so merge the
  PR before publishing the offer.

## 4. Partner Center

- [ ] Plan → Technical configuration: version and package filename both set to the new version.
- [ ] Offer listing → **Search keywords must include the Sentinel GUID**
      `f1de974b-f438-4719-b423-8bf704ba2aef`. Without it the solution does not appear in
      Microsoft Sentinel at all, and only three keywords are allowed — do not let it be pushed out.
- [ ] Plan → Availability: `Hide plan` unchecked; offer not hidden; Azure regions set to Azure Global.
- [ ] Offer listing → Description: this text is what the content hub shows. Keep it naming the
      Verity 471 backend, listing the content counts, and linking `ReleaseNotes.md`.

## 5. After publishing

Microsoft's documented window for a published offer to reach the Sentinel content hub is
**3–5 days**. Verify it actually arrived rather than assuming — a Live offer in Partner Center
does not prove the catalog was refreshed:

```bash
az rest --method get --url "https://management.azure.com/subscriptions/<SUB>/resourceGroups/<RG>/providers/Microsoft.OperationalInsights/workspaces/<WS>/providers/Microsoft.SecurityInsights/contentProductPackages?api-version=2023-04-01-preview" \
  --query "value[?contains(properties.displayName,'Intel')].{name:properties.displayName,version:properties.version}"
```

Check in a workspace where the solution is **not installed**, so the number reflects the catalog
rather than a local installation. If the version is still the old one past the window, escalate to
the Microsoft Sentinel Solutions Onboarding Team (`AzureSentinelPartner@microsoft.com`) and open a
Partner Center support ticket, quoting the offer ID, plan ID, publish timestamp and the SHA-256 of
the published package.

## References

- [Guide to building Microsoft Sentinel solutions](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions#guide-to-building-microsoft-sentinel-solutions)
- [Publish SIEM solutions to Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/publish-sentinel-solutions)
- [Microsoft Sentinel solution lifecycle in Partner Center](https://learn.microsoft.com/azure/sentinel/sentinel-solutions-post-publish-tracking)
- [Release notes guidance](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/ReleaseNotesGuidance.md)
