[CmdletBinding()]
param(
    [switch]$SetupCredential,
    [switch]$ReplaceCredential,
    [switch]$TestCredentialStore,
    [switch]$LoopbackTesting,
    [switch]$RequireApiToken
)

$ErrorActionPreference = 'Stop'
if ($ReplaceCredential -and -not $SetupCredential) {
    throw '-ReplaceCredential can only be used together with -SetupCredential.'
}
if ($TestCredentialStore -and ($SetupCredential -or $ReplaceCredential)) {
    throw '-TestCredentialStore cannot be combined with credential setup options.'
}
if ($LoopbackTesting -and ($SetupCredential -or $ReplaceCredential -or $TestCredentialStore)) {
    throw '-LoopbackTesting can only be used when starting the backend.'
}

if (-not ('PatrolmanCredentialStore' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class PatrolmanCredentialStore
{
    private const int GenericCredential = 1;
    private const int PersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeFileTime
    {
        public int Low;
        public int High;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public NativeFileTime LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, int type, int flags, out IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref NativeCredential credential, int flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, int type, int flags);

    [DllImport("Advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public static bool Exists(string target)
    {
        IntPtr credential;
        if (CredRead(target, GenericCredential, 0, out credential))
        {
            CredFree(credential);
            return true;
        }

        int error = Marshal.GetLastWin32Error();
        if (error == ErrorNotFound)
            return false;
        throw new Win32Exception(error, "Windows Credential Manager could not check the PATROLMAN credential.");
    }

    public static string Read(string target)
    {
        IntPtr credential;
        if (!CredRead(target, GenericCredential, 0, out credential))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
                return null;
            throw new Win32Exception(error, "Windows Credential Manager could not read the PATROLMAN credential.");
        }

        try
        {
            NativeCredential value = (NativeCredential)Marshal.PtrToStructure(
                credential, typeof(NativeCredential));
            if (value.CredentialBlob == IntPtr.Zero ||
                value.CredentialBlobSize < 64 ||
                value.CredentialBlobSize > 2560 ||
                value.CredentialBlobSize % 2 != 0)
                throw new InvalidOperationException("The stored PATROLMAN credential is invalid.");

            return Marshal.PtrToStringUni(
                value.CredentialBlob, value.CredentialBlobSize / 2);
        }
        finally
        {
            NativeCredential value = (NativeCredential)Marshal.PtrToStructure(
                credential, typeof(NativeCredential));
            if (value.CredentialBlob != IntPtr.Zero)
            {
                for (int i = 0; i < value.CredentialBlobSize; i++)
                    Marshal.WriteByte(value.CredentialBlob, i, 0);
            }
            CredFree(credential);
        }
    }

    public static void Write(string target, string userName, IntPtr secret, int secretSize)
    {
        if (secret == IntPtr.Zero || secretSize < 64 || secretSize > 2560 || secretSize % 2 != 0)
            throw new InvalidOperationException("The API token must contain 32 to 1280 characters.");
        for (int i = 0; i < secretSize / 2; i++)
        {
            if (Marshal.ReadInt16(secret, i * 2) == 0)
                throw new InvalidOperationException("The API token contains an unsupported null character.");
        }

        IntPtr targetName = Marshal.StringToHGlobalUni(target);
        IntPtr user = Marshal.StringToHGlobalUni(userName);
        try
        {
            NativeCredential credential = new NativeCredential();
            credential.Type = GenericCredential;
            credential.TargetName = targetName;
            credential.CredentialBlobSize = secretSize;
            credential.CredentialBlob = secret;
            credential.Persist = PersistLocalMachine;
            credential.UserName = user;
            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Windows Credential Manager could not store the PATROLMAN credential.");
        }
        finally
        {
            Marshal.FreeHGlobal(user);
            Marshal.FreeHGlobal(targetName);
        }
    }

    public static void Delete(string target)
    {
        if (!CredDelete(target, GenericCredential, 0))
        {
            int error = Marshal.GetLastWin32Error();
            if (error != ErrorNotFound)
                throw new Win32Exception(error, "Windows Credential Manager could not remove the temporary test credential.");
        }
    }
}
'@
}

$credentialTarget = 'PATROLMAN/AVA_API_TOKEN'
if ($TestCredentialStore) {
    $testTarget = 'PATROLMAN/Startup-SelfTest/' + [Guid]::NewGuid().ToString('N')
    $testValue = 'synthetic-patrolman-credential-store-self-test'
    $testSecureValue = ConvertTo-SecureString $testValue -AsPlainText -Force
    $testPointer = [IntPtr]::Zero
    try {
        $testPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($testSecureValue)
        [PatrolmanCredentialStore]::Write(
            $testTarget,
            [Environment]::UserName,
            $testPointer,
            $testSecureValue.Length * 2
        )
        $readBack = [PatrolmanCredentialStore]::Read($testTarget)
        if ($readBack -cne $testValue) {
            throw 'Windows Credential Manager self-test failed.'
        }
        $readBack = $null
        Write-Output 'Windows Credential Manager self-test passed using a temporary synthetic credential.'
    }
    finally {
        [PatrolmanCredentialStore]::Delete($testTarget)
        if ($testPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($testPointer)
        }
        $testSecureValue.Dispose()
        $testValue = $null
        $readBack = $null
    }
    return
}

if ($SetupCredential) {
    if ([PatrolmanCredentialStore]::Exists($credentialTarget) -and -not $ReplaceCredential) {
        throw 'A PATROLMAN credential is already stored for this Windows user. Use -ReplaceCredential only if you are intentionally replacing it with your existing token.'
    }

    $secureToken = Read-Host 'Enter your EXISTING PATROLMAN API token' -AsSecureString
    $tokenPointer = [IntPtr]::Zero
    try {
        if ($secureToken.Length -lt 32) {
            throw 'The existing API token must contain at least 32 characters. No credential was stored.'
        }
        if ($secureToken.Length -gt 1280) {
            throw 'The API token exceeds the Windows Credential Manager size limit. No credential was stored.'
        }
        $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($secureToken)
        [PatrolmanCredentialStore]::Write(
            $credentialTarget,
            [Environment]::UserName,
            $tokenPointer,
            $secureToken.Length * 2
        )
        Write-Output 'Existing API token stored in Windows Credential Manager for this Windows user.'
    }
    finally {
        if ($tokenPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($tokenPointer)
        }
        $secureToken.Dispose()
    }
    return
}

$projectRoot = $PSScriptRoot
$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
$venvScripts = Join-Path $projectRoot '.venv\Scripts'
$gitleaksRoot = Join-Path $env:LOCALAPPDATA 'Temp\patrolman-gitleaks-test'

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "The project virtual environment was not found at '$python'. Please create it ('python -m venv .venv') and install dependencies before starting PATROLMAN."
}

# Verify core dependencies in .venv
$depCheck = & $python -c "import flask, sqlalchemy, werkzeug; print('OK')" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Required dependencies (Flask, SQLAlchemy, Werkzeug) are missing from .venv. Run '$venvScripts\pip install -r requirements.txt' to install them."
}

# Safely inspect project-root .env for configuration if present
$envFilePath = Join-Path $projectRoot '.env'
$envHasLocalRoots = $false
$configuredPort = 5055

if (Test-Path -LiteralPath $envFilePath -PathType Leaf) {
    $envLines = Get-Content -LiteralPath $envFilePath -ErrorAction SilentlyContinue
    foreach ($line in $envLines) {
        if ($line -match '^\s*(?:export\s+)?AVA_ALLOWED_LOCAL_ROOTS\s*=\s*(.+)$') {
            $val = $matches[1].Trim().Trim('"').Trim("'")
            if ($val.Length -gt 0) {
                $envHasLocalRoots = $true
            }
        }
        if ($line -match '^\s*(?:export\s+)?AVA_PORT\s*=\s*(\d+)') {
            [int]::TryParse($matches[1], [ref]$configuredPort) | Out-Null
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($env:AVA_PORT)) {
    [int]::TryParse($env:AVA_PORT, [ref]$configuredPort) | Out-Null
}

# An AVA_ALLOWED_LOCAL_ROOTS value already present in this environment is the
# operator's explicit authorization: keep it instead of replacing it with the
# fixture directory.
$localRoots = $env:AVA_ALLOWED_LOCAL_ROOTS
if (-not [string]::IsNullOrWhiteSpace($localRoots)) {
    Write-Output 'Using the AVA_ALLOWED_LOCAL_ROOTS already configured for this environment; the script does not add or replace local scan roots.'
}
elseif ($envHasLocalRoots) {
    Write-Output 'Using AVA_ALLOWED_LOCAL_ROOTS configured in project .env.'
    $localRoots = $null
}
else {
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        if (-not (Test-Path -LiteralPath $gitleaksRoot -PathType Container)) {
            New-Item -ItemType Directory -Path $gitleaksRoot -Force | Out-Null
        }
        $localRoots = $gitleaksRoot
        Write-Output 'Using synthetic local root fixture for file checks.'
    }
}

# Check for active listener on configured port to prevent silent collision or cryptic errors
$activeConn = Get-NetTCPConnection -LocalPort $configuredPort -State Listen -ErrorAction SilentlyContinue
if ($activeConn) {
    $owningPid = $activeConn[0].OwningProcess
    $owningProc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
    $procDesc = if ($owningProc) { "$($owningProc.ProcessName) (PID $owningPid)" } else { "PID $owningPid" }
    throw "Port $configuredPort is already in use by $procDesc. Stop that process or configure a free port via AVA_PORT in .env."
}

$trivyCache = Join-Path $env:LOCALAPPDATA 'PATROLMAN\trivy-cache'
New-Item -ItemType Directory -Path $trivyCache -Force | Out-Null

$token = [PatrolmanCredentialStore]::Read($credentialTarget)
$tokenFromStore = -not [string]::IsNullOrEmpty($token) -and $token.Length -ge 32 -and $token.Length -le 1280
if (-not $tokenFromStore) {
    $token = $null
    if (-not [string]::IsNullOrEmpty($env:AVA_API_TOKEN) -and $env:AVA_API_TOKEN.Length -ge 32) {
        Write-Output 'No Windows Credential Manager credential is stored; the AVA_API_TOKEN already configured for this environment is used unchanged. No token was generated or changed.'
    }
    elseif (Test-Path -LiteralPath (Join-Path $projectRoot '.env') -PathType Leaf) {
        Write-Output 'No Windows Credential Manager credential is stored; the backend will use the git-ignored project .env file if configured. The script does not read or display it. No token was generated or changed.'
    }
    elseif ($RequireApiToken -or ($env:AVA_REQUIRE_API_TOKEN -eq 'true')) {
        throw 'No valid existing API token is available and API token is required. Recover your existing token and run .\Start-Patrolman.ps1 -SetupCredential, or set AVA_API_TOKEN (or a .env file at the project root) before starting the backend.'
    }
    else {
        Write-Output 'No Windows Credential Manager credential or AVA_API_TOKEN is configured. Starting PATROLMAN in normal website mode (web session authentication enabled, optional Bearer-token API access disabled).'
    }
}

$previousToken = [Environment]::GetEnvironmentVariable('AVA_API_TOKEN', 'Process')
$previousRoots = [Environment]::GetEnvironmentVariable('AVA_ALLOWED_LOCAL_ROOTS', 'Process')
$previousTargets = [Environment]::GetEnvironmentVariable('AVA_ALLOWED_TARGETS', 'Process')
$previousPrivateTargets = [Environment]::GetEnvironmentVariable('AVA_ALLOW_PRIVATE_TARGETS', 'Process')
$previousTrivyScanners = [Environment]::GetEnvironmentVariable('AVA_TRIVY_SCANNERS', 'Process')
$previousTrivyCache = [Environment]::GetEnvironmentVariable('AVA_TRIVY_CACHE_DIR', 'Process')
$previousDisableCExt = [Environment]::GetEnvironmentVariable('DISABLE_SQLALCHEMY_CEXT', 'Process')
$previousPath = $env:PATH
$locationPushed = $false
$backendExitCode = 0
try {
    Push-Location $projectRoot
    $locationPushed = $true
    if ($tokenFromStore) {
        $env:AVA_API_TOKEN = $token
    }
    if (-not [string]::IsNullOrWhiteSpace($localRoots)) {
        $env:AVA_ALLOWED_LOCAL_ROOTS = $localRoots
    }
    $env:AVA_TRIVY_SCANNERS = 'misconfig,secret'
    $env:AVA_TRIVY_CACHE_DIR = $trivyCache
    if ($LoopbackTesting) {
        $env:AVA_ALLOWED_TARGETS = '127.0.0.1'
        $env:AVA_ALLOW_PRIVATE_TARGETS = 'true'
    }
    # Enforce pure-Python SQLAlchemy mode to ensure full compatibility with
    # Windows Defender Application Control (WDAC), AppLocker, and strict code integrity policies.
    $env:DISABLE_SQLALCHEMY_CEXT = '1'

    $env:PATH = $venvScripts + [IO.Path]::PathSeparator + $previousPath

    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  PATROLMAN Assessment Platform -- Backend Startup" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Python:       $python"
    Write-Host "  Backend URL:  http://127.0.0.1:$configuredPort"
    Write-Host "  Frontend URL: http://127.0.0.1:5173"
    Write-Host "  WDAC Safety:  Pure-Python mode (DISABLE_SQLALCHEMY_CEXT=1)"
    Write-Host "============================================================" -ForegroundColor Cyan

    & $python -m backend
    $backendExitCode = $LASTEXITCODE
}
finally {
    $token = $null
    $tokenFromStore = $false
    $localRoots = $null
    if ($null -eq $previousToken) {
        Remove-Item Env:AVA_API_TOKEN -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_API_TOKEN = $previousToken
    }
    if ($null -eq $previousRoots) {
        Remove-Item Env:AVA_ALLOWED_LOCAL_ROOTS -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_ALLOWED_LOCAL_ROOTS = $previousRoots
    }
    if ($null -eq $previousTargets) {
        Remove-Item Env:AVA_ALLOWED_TARGETS -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_ALLOWED_TARGETS = $previousTargets
    }
    if ($null -eq $previousPrivateTargets) {
        Remove-Item Env:AVA_ALLOW_PRIVATE_TARGETS -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_ALLOW_PRIVATE_TARGETS = $previousPrivateTargets
    }
    if ($null -eq $previousTrivyScanners) {
        Remove-Item Env:AVA_TRIVY_SCANNERS -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_TRIVY_SCANNERS = $previousTrivyScanners
    }
    if ($null -eq $previousTrivyCache) {
        Remove-Item Env:AVA_TRIVY_CACHE_DIR -ErrorAction SilentlyContinue
    }
    else {
        $env:AVA_TRIVY_CACHE_DIR = $previousTrivyCache
    }
    if ($null -eq $previousDisableCExt) {
        Remove-Item Env:DISABLE_SQLALCHEMY_CEXT -ErrorAction SilentlyContinue
    }
    else {
        $env:DISABLE_SQLALCHEMY_CEXT = $previousDisableCExt
    }
    $env:PATH = $previousPath
    if ($locationPushed) {
        Pop-Location
    }
    $previousToken = $null
    $previousRoots = $null
    $previousTargets = $null
    $previousPrivateTargets = $null
    $previousTrivyScanners = $null
    $previousTrivyCache = $null
    $previousDisableCExt = $null
    $previousPath = $null
}

if ($backendExitCode -ne 0) {
    throw "PATROLMAN backend exited with code $backendExitCode."
}
