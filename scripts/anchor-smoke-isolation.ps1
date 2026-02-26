# scripts/anchor-smoke-isolation.ps1
# ANCHOR tenant-isolation smoke test
# Exit 0 = pass, Exit 1 = fail
#
# Required env vars:
#   ANCHOR_BASE         e.g. https://anchor-api-prod.onrender.com
#   ANCHOR_ADMIN_TOKEN  admin token used with X-ANCHOR-ADMIN-TOKEN header
#
# Optional env vars:
#   ANCHOR_TEST_PASSWORD (defaults to TestPass!12345)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Fail([string]$msg) {
  Write-Host "FAIL: $msg" -ForegroundColor Red
  exit 1
}

function Ok([string]$msg) {
  Write-Host "OK: $msg" -ForegroundColor Green
}

function Get-Env([string]$name) {
  $v = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrWhiteSpace($v)) { return $null }
  return $v
}

function Ensure-Env([string]$name) {
  $v = Get-Env $name
  if ($null -eq $v) { Fail "Missing env var: $name" }
  return $v
}

function Has-Prop($obj, [string]$propName) {
  if ($null -eq $obj) { return $false }
  return ($obj.PSObject.Properties.Match($propName).Count -gt 0)
}

function Get-Prop($obj, [string]$propName) {
  # StrictMode-safe: never throws if property is missing
  if ($null -eq $obj) { return $null }
  $p = $obj.PSObject.Properties[$propName]
  if ($null -eq $p) { return $null }
  return $p.Value
}

function Invoke-Json([string]$method, [string]$url, [hashtable]$headers, $bodyObj = $null) {
  $params = @{
    Method  = $method
    Uri     = $url
    Headers = $headers
  }
  if ($null -ne $bodyObj) {
    $params["ContentType"] = "application/json"
    $params["Body"] = ($bodyObj | ConvertTo-Json -Depth 20)
  }
  return Invoke-RestMethod @params
}

function Invoke-Text([string]$method, [string]$url, [hashtable]$headers) {
  return (Invoke-WebRequest -UseBasicParsing -Method $method -Uri $url -Headers $headers).Content
}

function Invoke-ExpectHttp([string]$method, [string]$url, [hashtable]$headers, [int]$expectedStatus, $bodyObj = $null) {
  try {
    if ($null -ne $bodyObj) {
      Invoke-Json $method $url $headers $bodyObj | Out-Null
    } else {
      Invoke-Json $method $url $headers $null | Out-Null
    }
    Fail "Expected HTTP $expectedStatus but request succeeded: $method $url"
  } catch {
    $resp = $_.Exception.Response
    if ($null -eq $resp) {
      Fail "Request failed but no HTTP response available: $($_.Exception.Message)"
    }
    $code = [int]$resp.StatusCode
    if ($code -ne $expectedStatus) {
      $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
      $body = $reader.ReadToEnd()
      Fail "Expected HTTP $expectedStatus but got HTTP $code. Body: $body"
    }
    return $true
  }
}

function New-RandomString([string]$prefix) {
  return "$prefix" + (Get-Random)
}

function Bootstrap-Clinic([string]$base, [string]$adminToken, [string]$name, [string]$email) {
  # IMPORTANT: make smoke clinics cheap + short-lived (mitigation for running on PROD often)
  $slug = New-RandomString "smoke-"
  $body = @{
    clinic_name               = $name
    clinic_slug               = $slug
    admin_email               = $email
    data_region               = "UK"
    retention_days_governance = 1        # minimize accumulation
    retention_days_ops        = 1        # minimize accumulation
    export_enabled            = $false
    invite_valid_days         = 1        # short-lived invites
    subscription_tier         = "smoke"  # tag for future cleanup tooling
  }

  $headers = @{
    "X-ANCHOR-ADMIN-TOKEN" = $adminToken
    "Content-Type"         = "application/json"
  }

  $boot = Invoke-Json "POST" "$base/v1/admin/bootstrap/clinic" $headers $body

  if (-not (Has-Prop $boot "clinic_slug") -or [string]::IsNullOrWhiteSpace([string]$boot.clinic_slug) -or
      -not (Has-Prop $boot "invite_token") -or [string]::IsNullOrWhiteSpace([string]$boot.invite_token) -or
      -not (Has-Prop $boot "clinic_id") -or [string]::IsNullOrWhiteSpace([string]$boot.clinic_id)) {
    Fail "Bootstrap response missing expected fields. Response: $($boot | ConvertTo-Json -Depth 10)"
  }

  return $boot
}

function Accept-Invite([string]$base, [string]$clinicSlug, [string]$email, [string]$inviteToken, [string]$password) {
  $body = @{
    clinic_slug   = $clinicSlug
    email         = $email
    invite_token  = $inviteToken
    password      = $password
  }
  $headers = @{ "Content-Type" = "application/json" }

  $acc = Invoke-Json "POST" "$base/v1/clinic/auth/invite/accept" $headers $body

  if (-not (Has-Prop $acc "access_token") -or [string]::IsNullOrWhiteSpace([string]$acc.access_token) -or
      -not (Has-Prop $acc "clinic_id") -or [string]::IsNullOrWhiteSpace([string]$acc.clinic_id) -or
      -not (Has-Prop $acc "clinic_user_id") -or [string]::IsNullOrWhiteSpace([string]$acc.clinic_user_id)) {
    Fail "Invite accept response missing expected fields. Response: $($acc | ConvertTo-Json -Depth 10)"
  }

  return $acc
}

function Portal-Submit([string]$base, [string]$jwt, [string]$mode, [string]$text) {
  $body = @{ mode = $mode; text = $text }
  $headers = @{
    "Authorization" = "Bearer $jwt"
    "Content-Type"  = "application/json"
  }
  return Invoke-Json "POST" "$base/v1/portal/submit" $headers $body
}

function Portal-Dashboard([string]$base, [string]$jwt) {
  $headers = @{ "Authorization" = "Bearer $jwt" }
  return Invoke-Json "GET" "$base/v1/portal/dashboard" $headers $null
}

function Portal-Receipt([string]$base, [string]$jwt, [string]$requestId) {
  if ([string]::IsNullOrWhiteSpace($requestId)) {
    Fail "Portal-Receipt called with empty requestId"
  }
  $headers = @{ "Authorization" = "Bearer $jwt" }
  return Invoke-Json "GET" "$base/v1/portal/receipt/$requestId" $headers $null
}

function Portal-ExportCsv([string]$base, [string]$jwt, [string]$fromIso, [string]$toIso) {
  $from = [System.Uri]::EscapeDataString($fromIso)
  $to   = [System.Uri]::EscapeDataString($toIso)
  $headers = @{ "Authorization" = "Bearer $jwt" }
  return Invoke-Text "GET" "$base/v1/portal/export.csv?from=$from&to=$to" $headers
}

function Extract-RequestId($submitResp) {
  # StrictMode-safe extraction: never dereference missing properties directly.
  # Shape A: { request_id: "..." }
  $rid = Get-Prop $submitResp "request_id"
  if (-not [string]::IsNullOrWhiteSpace([string]$rid)) {
    return [string]$rid
  }

  # Shape B: { receipt: { request_id: "..." } } or { receipt: { id: "..." } }
  $receipt = Get-Prop $submitResp "receipt"
  if ($receipt) {
    $rid2 = Get-Prop $receipt "request_id"
    if (-not [string]::IsNullOrWhiteSpace([string]$rid2)) {
      return [string]$rid2
    }
    $id2 = Get-Prop $receipt "id"
    if (-not [string]::IsNullOrWhiteSpace([string]$id2)) {
      return [string]$id2
    }
  }

  # Shape C: { governance_receipt: { request_id: "..." } } or { governance_receipt: { id: "..." } }
  $g = Get-Prop $submitResp "governance_receipt"
  if ($g) {
    $rid3 = Get-Prop $g "request_id"
    if (-not [string]::IsNullOrWhiteSpace([string]$rid3)) {
      return [string]$rid3
    }
    $id3 = Get-Prop $g "id"
    if (-not [string]::IsNullOrWhiteSpace([string]$id3)) {
      return [string]$id3
    }
  }

  return $null
}

# ===========================
# MAIN
# ===========================

$BASE  = Ensure-Env "ANCHOR_BASE"
$ADMIN = Ensure-Env "ANCHOR_ADMIN_TOKEN"
$PASSWORD = Get-Env "ANCHOR_TEST_PASSWORD"
if ($null -eq $PASSWORD) { $PASSWORD = "TestPass!12345" }

Write-Host "ANCHOR smoke test (tenant isolation)" -ForegroundColor Cyan
Write-Host "BASE=$BASE"

# 0) Admin auth-check
try {
  $auth = Invoke-Json "GET" "$BASE/v1/admin/auth-check" @{ "X-ANCHOR-ADMIN-TOKEN" = $ADMIN } $null
  if (-not (Has-Prop $auth "status") -or $auth.status -ne "ok") {
    Fail "admin/auth-check did not return status=ok. Response: $($auth | ConvertTo-Json -Depth 10)"
  }
  Ok "Admin auth-check ok"
} catch {
  Fail "Admin auth-check failed: $($_.Exception.Message)"
}

# 1) Bootstrap A and B
$emailA = ("smoke+a+" + (Get-Random) + "@test.local")
$emailB = ("smoke+b+" + (Get-Random) + "@test.local")

$bootA = Bootstrap-Clinic $BASE $ADMIN "SMOKE Clinic A (Isolation)" $emailA
$bootB = Bootstrap-Clinic $BASE $ADMIN "SMOKE Clinic B (Isolation)" $emailB

Ok ("Bootstrapped A: " + $bootA.clinic_slug + " (" + $bootA.clinic_id + ")")
Ok ("Bootstrapped B: " + $bootB.clinic_slug + " (" + $bootB.clinic_id + ")")

# 2) Accept invites -> JWTs
$accA = Accept-Invite $BASE $bootA.clinic_slug $emailA $bootA.invite_token $PASSWORD
$accB = Accept-Invite $BASE $bootB.clinic_slug $emailB $bootB.invite_token $PASSWORD

$tokenA = $accA.access_token
$tokenB = $accB.access_token

Ok "Accepted invite A -> JWT issued"
Ok "Accepted invite B -> JWT issued"

# 3) Submit marker to A
$marker  = "isotest-" + (Get-Random)
$submitA = Portal-Submit $BASE $tokenA "clinical_note" "Clinic A marker: $marker"

$requestId = Extract-RequestId $submitA
if ([string]::IsNullOrWhiteSpace($requestId)) {
  Fail "portal/submit response missing request_id. Response: $($submitA | ConvertTo-Json -Depth 20)"
}

Ok "Submitted to A -> request_id=$requestId"

# 4) A receipt must exist + match requestId
$receiptA = Portal-Receipt $BASE $tokenA $requestId

$receiptOk = $false
if (Has-Prop $receiptA "receipt" -and $receiptA.receipt -and Has-Prop $receiptA.receipt "request_id") {
  if ([string]$receiptA.receipt.request_id -eq $requestId) { $receiptOk = $true }
} elseif (Has-Prop $receiptA "request_id") {
  if ([string]$receiptA.request_id -eq $requestId) { $receiptOk = $true }
}

if (-not $receiptOk) {
  Fail "A receipt missing or mismatched request_id. Response: $($receiptA | ConvertTo-Json -Depth 20)"
}
Ok "A can read its receipt"

# 5) B must NOT be able to read A receipt (expect 404)
Invoke-ExpectHttp "GET" "$BASE/v1/portal/receipt/$requestId" @{ "Authorization" = "Bearer $tokenB" } 404 | Out-Null
Ok "B cannot read A receipt (404 as expected)"

# 6) Dashboards: A should include request_id, B should not
$dashA = Portal-Dashboard $BASE $tokenA
$dashB = Portal-Dashboard $BASE $tokenB

$dashAJson = ($dashA | ConvertTo-Json -Depth 80)
$dashBJson = ($dashB | ConvertTo-Json -Depth 80)

if ($dashAJson -notlike "*$requestId*") {
  Fail "A dashboard does not contain A request_id (unexpected). A dashboard: $dashAJson"
}
Ok "A dashboard contains its request_id"

if ($dashBJson -like "*$requestId*") {
  Fail "B dashboard contains A request_id (ISOLATION FAILURE). B dashboard: $dashBJson"
}
Ok "B dashboard does not contain A request_id"

# 7) CSV exports: A should include request_id, B should not
$fromIso = (Get-Date).ToUniversalTime().AddDays(-2).ToString("yyyy-MM-ddTHH:mm:ss+00:00")
$toIso   = (Get-Date).ToUniversalTime().AddDays( 2).ToString("yyyy-MM-ddTHH:mm:ss+00:00")

$csvA = Portal-ExportCsv $BASE $tokenA $fromIso $toIso
$csvB = Portal-ExportCsv $BASE $tokenB $fromIso $toIso

if ($csvA -notlike "*$requestId*") {
  Fail "A export.csv does not include A request_id (unexpected)."
}
Ok "A export.csv contains its request_id"

if ($csvB -like "*$requestId*") {
  Fail "B export.csv contains A request_id (ISOLATION FAILURE)."
}
Ok "B export.csv does not contain A request_id"

Write-Host ""
Write-Host "PASS: Tenant isolation smoke test completed successfully." -ForegroundColor Green
exit 0