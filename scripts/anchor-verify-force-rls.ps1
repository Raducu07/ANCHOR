# scripts/anchor-verify-force-rls.ps1
# Verifies that the admin RLS self-test endpoint is reachable and that
# critical tenant tables are RLS-enabled and FORCE-RLS-enabled where required.

param(
  [Parameter(Mandatory = $true)]
  [string]$Base,

  [Parameter(Mandatory = $true)]
  [string]$AdminToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$msg) {
  throw $msg
}

function Ok([string]$msg) {
  Write-Host "OK: $msg" -ForegroundColor Green
}

function Has-Prop($obj, [string]$propName) {
  if ($null -eq $obj) { return $false }
  return ($obj.PSObject.Properties.Match($propName).Count -gt 0)
}

function Get-Prop($obj, [string]$propName) {
  if ($null -eq $obj) { return $null }
  $p = $obj.PSObject.Properties[$propName]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function Require-RlsState(
  [string]$label,
  $state,
  [bool]$requireForce = $true
) {
  if ($null -eq $state) {
    Fail "$label metadata missing from self-test response"
  }

  $rlsEnabled = [bool](Get-Prop $state "relrowsecurity")
  $forceRls   = [bool](Get-Prop $state "relforcerowsecurity")

  if (-not $rlsEnabled) {
    Fail "$label RLS is not enabled"
  }

  if ($requireForce -and -not $forceRls) {
    Fail "$label FORCE RLS is not enabled"
  }

  Write-Host ("OK: {0} RLS={1} FORCE={2}" -f $label, $rlsEnabled, $forceRls) -ForegroundColor Green
}

$headers = @{
  "Authorization" = "Bearer $AdminToken"
}

$selfTest = Invoke-RestMethod -Method GET -Uri "$Base/v1/admin/ops/rls-self-test" -Headers $headers

if (-not (Has-Prop $selfTest "status")) {
  Fail "Self-test response missing status"
}

if ([string]$selfTest.status -ne "ok") {
  Fail "Self-test returned non-ok status: $($selfTest | ConvertTo-Json -Depth 20)"
}

$debug = Get-Prop $selfTest "debug"
if ($null -eq $debug) {
  Fail "Self-test response missing debug payload"
}

# Core tenant tables
Require-RlsState "rls_clinics" (Get-Prop $debug "rls_clinics") $true
Require-RlsState "rls_clinic_users" (Get-Prop $debug "rls_clinic_users") $true

# Governance events field name changed during M3 cleanup:
# old: rls_governance_events
# new: rls_clinic_governance_events
$govRls = $null
if (Has-Prop $debug "rls_clinic_governance_events") {
  $govRls = Get-Prop $debug "rls_clinic_governance_events"
}
elseif (Has-Prop $debug "rls_governance_events") {
  $govRls = Get-Prop $debug "rls_governance_events"
}
else {
  Fail "Self-test response missing governance-events RLS field"
}

Require-RlsState "governance events" $govRls $true

# Other tenant-hard tables expected to be FORCE-RLS protected
Require-RlsState "rls_ops_metrics_events" (Get-Prop $debug "rls_ops_metrics_events") $true
Require-RlsState "rls_clinic_policies" (Get-Prop $debug "rls_clinic_policies") $true
Require-RlsState "rls_clinic_policy_state" (Get-Prop $debug "rls_clinic_policy_state") $true
Require-RlsState "rls_clinic_privacy_profile" (Get-Prop $debug "rls_clinic_privacy_profile") $true

# Admin/platform audit events are checked for visibility, but FORCE RLS is optional
# unless you later decide this table is tenant-scoped.
$adminAudit = Get-Prop $debug "rls_admin_audit_events"
if ($null -ne $adminAudit) {
  $rlsEnabled = [bool](Get-Prop $adminAudit "relrowsecurity")
  $forceRls   = [bool](Get-Prop $adminAudit "relforcerowsecurity")
  if (-not $rlsEnabled) {
    Fail "rls_admin_audit_events RLS is not enabled"
  }
  Write-Host ("OK: rls_admin_audit_events RLS={0} FORCE={1} (FORCE optional by design)" -f $rlsEnabled, $forceRls) -ForegroundColor Green
}

exit 0