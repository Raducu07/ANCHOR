# scripts/anchor-verify-force-rls.ps1
# Verifies:
# - /v1/admin/ops/rls-self-test returns status=ok
# - FORCE+ENABLE RLS coverage for key tenant tables is present in debug

param(
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Base,
  [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$AdminToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Avoid stale state in interactive shells
$r = $null

$r = Invoke-RestMethod -Method GET "$Base/v1/admin/ops/rls-self-test" `
  -Headers @{ Authorization = "Bearer $AdminToken" }

if ($null -eq $r) { throw "No response from rls-self-test" }
if ($r.status -ne "ok") { throw "RLS isolation test failed: status=$($r.status)" }
if ($null -eq $r.debug) { throw "Missing debug in rls-self-test response" }

$targets = @(
  "rls_clinics",
  "rls_clinic_users",
  "rls_governance_events",
  "rls_ops_metrics_events",
  "rls_clinic_policies",
  "rls_clinic_policy_state",
  "rls_clinic_privacy_profile"
)

foreach ($k in $targets) {
  if (-not $r.debug.$k) { throw "Missing debug key: $k" }

  $row = $r.debug.$k
  if ($row.relrowsecurity -ne $true) { throw "${k}: relrowsecurity is not true" }
  if ($row.relforcerowsecurity -ne $true) { throw "${k}: relforcerowsecurity is not true" }

  Write-Host "OK: $k RLS=true FORCE=true" -ForegroundColor Green
}

Write-Host "PASS: FORCE RLS coverage verified." -ForegroundColor Green