#Microsoft.RDInfra.RDPowerShell and Get-Package both require powershell 5.0 or higher.
#Requires -Version 5.0

<#
.SYNOPSIS
Common functions to be used by DSC scripts
#>

# Setting to Tls12 due to Azure web app security requirements
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

<# [CalledByARMTemplate] #>
function Write-Log {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        # note: can't use variable named '$Error': https://github.com/PowerShell/PSScriptAnalyzer/blob/master/RuleDocumentation/AvoidAssignmentToAutomaticVariable.md
        [switch]$Err
    )
     
    try {
        $DateTime = Get-Date -Format "MM-dd-yy HH:mm:ss"
        $Invocation = "$($MyInvocation.MyCommand.Source):$($MyInvocation.ScriptLineNumber)"

        if ($Err) {
            $Message = "[ERROR] $Message"
        }
        
        Add-Content -Value "$DateTime - $Invocation - $Message" -Path "$([environment]::GetEnvironmentVariable('TEMP', 'Machine'))\ScriptLog.log"
    }
    catch {
        throw [System.Exception]::new("Some error occurred while writing to log file with message: $Message", $PSItem.Exception)
    }
}

function AddDefaultUsers {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $true)]
        [string]$ApplicationGroupName,

        [Parameter(Mandatory = $false)]
        [string]$DefaultUsers
    )
    $ErrorActionPreference = "Stop"

    Write-Log "Adding Default users. Argument values: App Group: $ApplicationGroupName, TenantName: $TenantName, HostPoolName: $HostPoolName, DefaultUsers: $DefaultUsers"

    # Sanitizing DefaultUsers string
    $DefaultUsers = $DefaultUsers.Replace("`"", "").Replace("'", "").Replace(" ", "")

    if (-not ([string]::IsNullOrEmpty($DefaultUsers))) {
        $UserList = $DefaultUsers.split(",", [System.StringSplitOptions]::RemoveEmptyEntries)

        foreach ($user in $UserList) {
            try {
                Add-RdsAppGroupUser -TenantName "$TenantName" -HostPoolName "$HostPoolName" -AppGroupName $ApplicationGroupName -UserPrincipalName $user
                Write-Log "Successfully assigned user $user to App Group: $ApplicationGroupName. Other details -> TenantName: $TenantName, HostPoolName: $HostPoolName."
            }
            catch {
                Write-Log -Err "An error ocurred assigining user $user to App Group $ApplicationGroupName. Other details -> TenantName: $TenantName, HostPoolName: $HostPoolName."
                Write-Log -Err ($PSItem | Format-List -Force | Out-String)
            }
        }
    }
}

function ValidateServicePrincipal {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$isServicePrincipal,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AadTenantId = ""
    )

    if ($isServicePrincipal -eq "True") {
        if ([string]::IsNullOrEmpty($AadTenantId)) {
            throw "When IsServicePrincipal = True, AadTenant ID is mandatory. Please provide a valid AadTenant ID."
        }
    }
}

function Is1809OrLater {
    $OSVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    if ($null -ne $OSVersionInfo) {
        if ($null -ne $OSVersionInfo.ReleaseId) {
            Write-Log -Message "Build: $($OSVersionInfo.ReleaseId)"
            $rdshIs1809OrLaterBool = @{$true = $true; $false = $false }[$OSVersionInfo.ReleaseId -ge 1809]
        }
    }
    return $rdshIs1809OrLaterBool
}

<# [CalledByARMTemplate] #>
function ExtractDeploymentAgentZipFile {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$DeployAgentLocation
    )

    if (Test-Path $DeployAgentLocation) {
        Remove-Item -Path $DeployAgentLocation -Force -Confirm:$false -Recurse
    }
    
    New-Item -Path "$DeployAgentLocation" -ItemType directory -Force
    
    # Locating and extracting DeployAgent.zip
    $DeployAgentFromRepo = (LocateFile -Name 'DeployAgent.zip' -SearchPath $ScriptPath -Recurse)
    
    Write-Log -Message "Extracting 'Deployagent.zip' file into '$DeployAgentLocation' folder inside VM"
    Expand-Archive $DeployAgentFromRepo -DestinationPath "$DeployAgentLocation"
}

<# [CalledByARMTemplate] #>
function isRdshServer {
    $rdshIsServer = $true

    $OSVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    
    if ($null -ne $OSVersionInfo) {
        if ($null -ne $OSVersionInfo.InstallationType) {
            $rdshIsServer = @{$true = $true; $false = $false }[$OSVersionInfo.InstallationType -eq "Server"]
        }
    }

    return $rdshIsServer
}


<#
.Description
Call this function using dot source notation like ". AuthenticateRdsAccount" because the Add-RdsAccount function this calls creates variables using the AllScope option that other WVD poweshell module functions like Set-RdsContext require. Note that this creates a variable named "$authentication" that will overwrite any existing variable with that name in the scope this is dot sourced to.

Calling code should set $ErrorActionPreference = "Stop" before calling this function to ensure that detailed error information is thrown if there is an error.
#>
function AuthenticateRdsAccount {
    param(
        [Parameter(mandatory = $true)]
        [string]$DeploymentUrl,
    
        [Parameter(mandatory = $true)]
        [pscredential]$Credential,
    
        [switch]$ServicePrincipal,
    
        [Parameter(mandatory = $false)]
        [AllowEmptyString()]
        [string]$TenantId = ""
    )

    if ($ServicePrincipal) {
        Write-Log -Message "Authenticating using service principal $($Credential.username) and Tenant id: $TenantId"
    }
    else {
        $PSBoundParameters.Remove('ServicePrincipal')
        $PSBoundParameters.Remove('TenantId')
        Write-Log -Message "Authenticating using user $($Credential.username)"
    }
    
    $authentication = $null
    try {
        $authentication = Add-RdsAccount @PSBoundParameters
        if (!$authentication) {
            throw $authentication
        }
    }
    catch {
        throw [System.Exception]::new("Error authenticating Windows Virtual Desktop account, ServicePrincipal = $ServicePrincipal", $PSItem.Exception)
    }
    
    Write-Log -Message "Windows Virtual Desktop account authentication successful. Result:`n$($authentication | Out-String)"
}

function SetTenantGroupContextAndValidate {
    param(
        [Parameter(mandatory = $true)]
        [string]$TenantGroupName,

        [Parameter(mandatory = $true)]
        [string]$TenantName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    # Set context to the appropriate tenant group
    $currentTenantGroupName = (Get-RdsContext).TenantGroupName
    if ($TenantGroupName -ne $currentTenantGroupName) {
        Write-Log -Message "Running switching to the $TenantGroupName context"

        try {
            #As of Microsoft.RDInfra.RDPowerShell version 1.0.1534.2001 this throws a System.NullReferenceException when the TenantGroupName doesn't exist.
            Set-RdsContext -TenantGroupName $TenantGroupName
        }
        catch {
            throw [System.Exception]::new("Error setting RdsContext using tenant group ""$TenantGroupName"", this may be caused by the tenant group not existing or the user not having access to the tenant group", $PSItem.Exception)
        }
    }
    
    $tenants = $null
    try {
        $tenants = (Get-RdsTenant -Name $TenantName)
    }
    catch {
        throw [System.Exception]::new("Error getting the tenant with name ""$TenantName"", this may be caused by the tenant not existing or the account doesn't have access to the tenant", $PSItem.Exception)
    }
    
    if (!$tenants) {
        throw "No tenant with name ""$TenantName"" exists or the account doesn't have access to it."
    }
}

function LocateFile {
    param (
        [Parameter(mandatory = $true)]
        [string]$Name,
        [string]$SearchPath = '.',
        [switch]$Recurse
    )
    
    Write-Log -Message "Locating '$Name' within: '$SearchPath'"
    $Path = (Get-ChildItem "$SearchPath\" -Filter $Name -Recurse:$Recurse).FullName
    if ((-not $Path) -or (-not (Test-Path $Path))) {
        throw "'$Name' file not found at '$SearchPath'"
    }
    if (@($Path).Length -ne 1) {
        throw "Multiple '$Name' files found at '$SearchPath': [`n$Path`n]"
    }

    return $Path
}

function ImportRDPSMod {
    param(
        [string]$Source = 'attached',
        [string]$ArtifactsPath
    )

    $ErrorActionPreference = "Stop"

    $ModName = 'Microsoft.RDInfra.RDPowershell'
    $Mod = (get-module $ModName)

    if ($Mod) {
        Write-Log -Message 'RD PowerShell module already imported (Not going to re-import)'
        return
    }
        
    $Path = 'C:\_tmp_RDPSMod\'
    if (test-path $Path) {
        Write-Log -Message "Remove tmp dir '$Path'"
        Remove-Item -Path $Path -Force -Recurse
    }
    
    if ($Source -eq 'attached') {
        if ((-not $ArtifactsPath) -or (-not (test-path $ArtifactsPath))) {
            throw "invalid param: ArtifactsPath = '$ArtifactsPath'"
        }

        # Locating and extracting PowerShellModules.zip
        $ZipPath = (LocateFile -Name 'PowerShellModules.zip' -SearchPath $ArtifactsPath -Recurse)

        Write-Log -Message "Extracting RD PowerShell module file '$ZipPath' into '$Path'"
        Expand-Archive $ZipPath -DestinationPath $Path -Force
        Write-Log -Message "Successfully extracted RD PowerShell module file '$ZipPath' into '$Path'"
    }
    else {
        $Version = ($Source.Trim().ToLower() -split 'gallery@')[1]
        if ($null -eq $Version -or $Version.Trim() -eq '') {
            throw "invalid param: Source = $Source"
        }

        Write-Log -Message "Downloading RD PowerShell module (version: v$Version) from PowerShell Gallery into '$Path'"
        if ($Version -eq 'latest') {
            Save-Module -Name $ModName -Path $Path -Force
        }
        else {
            Save-Module -Name $ModName -Path $Path -Force -RequiredVersion (new-object System.Version($Version))
        }
        Write-Log -Message "Successfully downloaded RD PowerShell module (version: v$Version) from PowerShell Gallery into '$Path'"
    }

    $DLLPath = (LocateFile -Name "$ModName.dll" -SearchPath $Path -Recurse)

    Write-Log -Message "Importing RD PowerShell module DLL '$DLLPath"
    Import-Module $DLLPath -Force
    Write-Log -Message "Successfully imported RD PowerShell module DLL '$DLLPath"
}

<# [CalledByARMTemplate] #>
function GetCurrSessionHostName {
    $Wmi = (Get-WmiObject win32_computersystem)
    return "$($Wmi.DNSHostName).$($Wmi.Domain)"
}

<# [CalledByARMTemplate] #>
function GetSessionHostDesiredStates {
    return ('Available', 'NeedsAssistance')
}

<# [CalledByARMTemplate] #>
function IsRDAgentRegistryValidForRegistration {
    $ErrorActionPreference = "Stop"

    $RDInfraReg = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RDInfraAgent' -ErrorAction SilentlyContinue
    if (!$RDInfraReg) {
        return @{
            result = $false;
            msg    = 'RD Infra registry missing';
        }
    }
    Write-Log -Message 'RD Infra registry exists'

    Write-Log -Message 'Check RD Infra registry values to see if RD Agent is registered'
    if ($RDInfraReg.RegistrationToken -ne '') {
        return @{
            result = $false;
            msg    = 'RegistrationToken in RD Infra registry is not empty'
        }
    }
    if ($RDInfraReg.IsRegistered -ne 1) {
        return @{
            result = $false;
            msg    = "Value of 'IsRegistered' in RD Infra registry is $($RDInfraReg.IsRegistered), but should be 1"
        }
    }
    
    return @{
        result = $true
    }
}

<# [CalledByARMTemplate] indirectly because this is called by InstallRDAgents #>
function RunMsiWithRetry {
    param(
        [Parameter(mandatory = $true)]
        [string]$programDisplayName,

        [Parameter(mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]$argumentList, #Must have at least 1 value

        [Parameter(mandatory = $true)]
        [string]$msiOutputLogPath,

        [Parameter(mandatory = $false)]
        [switch]$isUninstall,

        [Parameter(mandatory = $false)]
        [switch]$msiLogVerboseOutput
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

    if ($msiLogVerboseOutput) {
        $argumentList += "/l*vx+ ""$msiOutputLogPath""" 
    }
    else {
        $argumentList += "/liwemo+! ""$msiOutputLogPath"""
    }

    $retryTimeToSleepInSec = 30
    $retryCount = 0
    $sts = $null
    do {
        $modeAndDisplayName = ($(if ($isUninstall) { "Uninstalling" } else { "Installing" }) + " $programDisplayName")

        if ($retryCount -gt 0) {
            Write-Log -Message "Retrying $modeAndDisplayName in $retryTimeToSleepInSec seconds because it failed with Exit code=$sts This will be retry number $retryCount"
            Start-Sleep -Seconds $retryTimeToSleepInSec
        }

        Write-Log -Message ( "$modeAndDisplayName" + $(if ($msiLogVerboseOutput) { " with verbose msi logging" } else { "" }))


        $processResult = Start-Process -FilePath "msiexec.exe" -ArgumentList $argumentList -Wait -Passthru
        $sts = $processResult.ExitCode

        $retryCount++
    } 
    while ($sts -eq 1618 -and $retryCount -lt 20) # Error code 1618 is ERROR_INSTALL_ALREADY_RUNNING see https://docs.microsoft.com/en-us/windows/win32/msi/-msiexecute-mutex .

    if ($sts -eq 1618) {
        Write-Log -Err "Stopping retries for $modeAndDisplayName. The last attempt failed with Exit code=$sts which is ERROR_INSTALL_ALREADY_RUNNING"
        throw "Stopping because $modeAndDisplayName finished with Exit code=$sts"
    }
    else {
        Write-Log -Message "$modeAndDisplayName finished with Exit code=$sts"
    }

    return $sts
}


<#
.DESCRIPTION
Parse registration token to get claim section of the token

.PARAMETER token
The registration token

[CalledByARMTemplate]
#>
function ParseRegistrationToken {
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken
    )
 
    Set-StrictMode -Version 1.0
    $ClaimsSection = $RegistrationToken.Split(".")[1].Replace('-', '+').Replace('_', '/')
    while ($ClaimsSection.Length % 4) { 
        $ClaimsSection += "=" 
    }
    
    $ClaimsByteArray = [System.Convert]::FromBase64String($ClaimsSection)
    $ClaimsArray = [System.Text.Encoding]::ASCII.GetString($ClaimsByteArray)
    $Claims = $ClaimsArray | ConvertFrom-Json
    return $Claims
}

<#
.DESCRIPTION
Get Agent MSI endpoint. If the endpoint cannot be obtained, this method returns a null value to the caller

.PARAMETER BrokerAgentApi
AgentMsiController endpoint on broker, which will return the agent msi endpoints

.PARAMETER HostpoolId
The Hostpool Id

[CalledByARMTemplate]
#>
function GetAgentMSIEndpoint {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $BrokerAgentApi
    )

    Set-StrictMode -Version 1.0
    $ErrorActionPreference = "Stop"

    try {
        Write-Log -Message "Invoking broker agent api $BrokerAgentApi to get msi endpoint"
        $result = Invoke-WebRequest -Uri $BrokerAgentApi -UseBasicParsing
        $responseJson = $result.Content | ConvertFrom-Json
    }
    catch {
        $responseBody = $_.ErrorDetails.Message
        Write-Log -Err $responseBody
        return $null
    }

    Write-Log -Message "Obtained agent msi endpoint $($responseJson.agentEndpoint)"
    return $responseJson.agentEndpoint
}

<#
.DESCRIPTION
Download Agent MSI from storage blob if they are available

.PARAMETER AgentEndpoint
The Agent MSI storage blob endpoint which will downloaded on the session host

.PARAMETER AgentInstallerFolder
The destination folder to download the MSI

[CalledByARMTemplate]
#>
function DownloadAgentMSI {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PrivateLinkAgentEndpoint,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentDownloadFolder
    )
    
    Set-StrictMode -Version 1.0

    $AgentInstaller = $null

    try {
        Write-Log -Message "Trying to download agent msi from $AgentEndpoint"
        Invoke-WebRequest -Uri $AgentEndpoint -OutFile "$AgentDownloadFolder\RDAgent.msi"
        $AgentInstaller = Join-Path $AgentDownloadFolder "RDAgent.msi"
    } 
    catch {
        Write-Log -Err "Error while downloading agent msi from $AgentEndpoint"
        Write-Log -Err $_.Exception.Message
    }

    if (-not $AgentInstaller) {
        try {
            Write-Log -Message "Trying to download agent msi from $PrivateLinkAgentEndpoint"
            Invoke-WebRequest -Uri $AgentEndpoint -OutFile "$AgentDownloadFolder\RDAgent.msi"
            $AgentInstaller = Join-Path $AgentDownloadFolder "RDAgent.msi"
        } 
        catch {
            Write-Log -Err "Error while downloading agent msi from $PrivateLinkAgentEndpoint"
            Write-Log -Err $_.Exception.Message
        }
    }

    return $AgentInstaller
}

<#
.DESCRIPTION
Downloads the latest agent msi from storage blob.

.PARAMETER RegistrationToken
A Token that contains the Broker endpoint

.PARAMETER AgentInstallerFolder
The folder to which to download the agent msi

[CalledByARMTemplate]
#>
function GetAgentInstaller {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentInstallerFolder
    )

    Try {
        $ParsedToken = ParseRegistrationToken $RegistrationToken
        if (-not $ParsedToken.GlobalBrokerResourceIdUri) {
            Write-Log -Message "Unable to obtain broker agent check endpoint"
            return
        }

        $BrokerAgentUri = [System.UriBuilder] $ParsedToken.GlobalBrokerResourceIdUri
        $BrokerAgentUri.Path = "api/agentMsi/v1/agentVersion"
        $BrokerAgentUri = $BrokerAgentUri.Uri.AbsoluteUri
        Write-Log -Message "Obtained broker agent api $BrokerAgentUri"

        $AgentMSIEndpointUri = [System.UriBuilder] (GetAgentMSIEndpoint $BrokerAgentUri)
        if (-not $AgentMSIEndpointUri) {
            Write-Log -Message "Unable to get Agent MSI endpoints from storage blob"
            return
        }

        $AgentDownloadFolder = New-Item -Path $AgentInstallerFolder -Name "RDAgent" -ItemType "directory" -Force
        $PrivateLinkAgentMSIEndpointUri = [System.UriBuilder] $AgentMSIEndpointUri.Uri.AbsoluteUri
        $PrivateLinkAgentMSIEndpointUri.Host = "$($ParsedToken.EndpointPoolId).$($AgentMSIEndpointUri.Host)"
        Write-Log -Message "Attempting to download agent msi from $($AgentMSIEndpointUri.Uri.AbsoluteUri), or $($AgentMSIEndpointUri.Uri.AbsoluteUri)"

        $AgentInstaller = DownloadAgentMSI $AgentMSIEndpointUri $PrivateLinkAgentMSIEndpointUri $AgentDownloadFolder
        if (-not $AgentInstaller) {
            Write-Log -Message "Failed to download agent msi from $AgentMSIEndpointUri"
        } else {
            Write-Log "Successfully downloaded the agent from $AgentMSIEndpointUri"
        }

        return $AgentInstaller
    } 
    Catch {
        Write-Log -Err "There was an error while downloading agent msi"
        Write-Log -Err $_.Exception.Message
    }
}

<#
.DESCRIPTION
Uninstalls any existing RDAgent BootLoader and RD Infra Agent installations and then installs the RDAgent BootLoader and RD Infra Agent using the specified registration token.

.PARAMETER AgentInstallerFolder
Required path to MSI installer file

.PARAMETER AgentBootServiceInstallerFolder
Required path to MSI installer file

[CalledByARMTemplate]
#>
function InstallRDAgents {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentInstallerFolder,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$AgentBootServiceInstallerFolder,
    
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RegistrationToken,
    
        [Parameter(mandatory = $false)]
        [switch]$EnableVerboseMsiLogging,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseAgentDownloadEndpoint = $false
    )

    $ErrorActionPreference = "Stop"

    Write-Log -Message "Boot loader folder is $AgentBootServiceInstallerFolder"
    $AgentBootServiceInstaller = LocateFile -SearchPath $AgentBootServiceInstallerFolder -Name "*.msi"

    if ($UseAgentDownloadEndpoint) {
        Write-Log -Message "Obtaining agent installer"
        $AgentInstaller = GetAgentInstaller $RegistrationToken $AgentInstallerFolder
        if (-not $AgentInstaller) {
            Write-Log -Message "Unable to download latest agent msi from storage blob. Using the agent msi from the extension."
        }
    }

    if (-not $AgentInstaller) {
        Write-Log -Message "Installing the bundled agent msi"
        $AgentInstaller = LocateFile -SearchPath $AgentInstallerFolder -Name "*.msi"
    }

    $msiNamesToUninstall = @(
        @{ msiName = "Remote Desktop Services Infrastructure Agent"; displayName = "RD Infra Agent"; logPath = "C:\Users\AgentUninstall.txt"}, 
        @{ msiName = "Remote Desktop Agent Boot Loader"; displayName = "RDAgentBootLoader"; logPath = "C:\Users\AgentBootLoaderUnInstall.txt"}
    )
    
    foreach($u in $msiNamesToUninstall) {
        while ($true) {
            try {
                $installedMsi = Get-Package -ProviderName msi -Name $u.msiName
            }
            catch {
                #Ignore the error if it was due to no packages being found.
                if ($PSItem.FullyQualifiedErrorId -eq "NoMatchFound,Microsoft.PowerShell.PackageManagement.Cmdlets.GetPackage") {
                    break
                }
    
                throw;
            }
    
            $oldVersion = $installedMsi.Version
            $productCodeParameter = $installedMsi.FastPackageReference
    
            RunMsiWithRetry -programDisplayName "$($u.displayName) $oldVersion" -isUninstall -argumentList @("/x $productCodeParameter", "/quiet", "/qn", "/norestart", "/passive") -msiOutputLogPath $u.logPath -msiLogVerboseOutput:$EnableVerboseMsiLogging
        }
    }

    Write-Log -Message "Installing RD Infra Agent on VM $AgentInstaller"
    RunMsiWithRetry -programDisplayName "RD Infra Agent" -argumentList @("/i $AgentInstaller", "/quiet", "/qn", "/norestart", "/passive", "REGISTRATIONTOKEN=$RegistrationToken") -msiOutputLogPath "C:\Users\AgentInstall.txt" -msiLogVerboseOutput:$EnableVerboseMsiLogging

    Write-Log -Message "Installing RDAgent BootLoader on VM $AgentBootServiceInstaller"
    RunMsiWithRetry -programDisplayName "RDAgent BootLoader" -argumentList @("/i $AgentBootServiceInstaller", "/quiet", "/qn", "/norestart", "/passive") -msiOutputLogPath "C:\Users\AgentBootLoaderInstall.txt" -msiLogVerboseOutput:$EnableVerboseMsiLogging

    $bootloaderServiceName = "RDAgentBootLoader"
    $startBootloaderRetryCount = 0
    while ( -not (Get-Service $bootloaderServiceName -ErrorAction SilentlyContinue)) {
        $retry = ($startBootloaderRetryCount -lt 6)
        $msgToWrite = "Service $bootloaderServiceName was not found. "
        if ($retry) { 
            $msgToWrite += "Retrying again in 30 seconds, this will be retry $startBootloaderRetryCount" 
            Write-Log -Message $msgToWrite
        } 
        else {
            $msgToWrite += "Retry limit exceeded" 
            Write-Log -Err $msgToWrite
            throw $msgToWrite
        }
            
        $startBootloaderRetryCount++
        Start-Sleep -Seconds 30
    }

    Write-Log -Message "Starting service $bootloaderServiceName"
    Start-Service $bootloaderServiceName
}
# SIG # Begin signature block
# MIIoTQYJKoZIhvcNAQcCoIIoPjCCKDoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxF4IaVUFJ8Ces
# y4JXjNfp1/NklOulcxm2VKtR5+nS/6CCDWowggY1MIIEHaADAgECAhMzAAAACWMn
# 7YqGMfm5AAAAAAAJMA0GCSqGSIb3DQEBDAUAMIGEMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1
# aWxkIFRvb2xzIFBDQSAyMDIwMB4XDTI0MDYxOTE4MTUzMVoXDTI1MDYxNzE4MTUz
# MVowgYQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNV
# BAMTJVdpbmRvd3MgSW50ZXJuYWwgQnVpbGQgVG9vbHMgQ29kZVNpZ24wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8hzd2IEs+Z6vJe1Ph36MjW51GBPHT
# ZZIYQRpyRgt+QuGPo4kbBnIiR1owrowXKYA4xiRiFq2nZOavdegFrxTAlFn1aCdQ
# 6ncidMVi4xUoY3AUyXAKXDL8wXDX1nmSpvT0HDm1c7QsIYCFNM4r7M6HaHA+k8JL
# jQyJN5piljfTiGTrnpJoBpbGMQluq8p11WX155BgWZ4EMAfh32nqO7HKXjZ6CFd2
# Cfn+8tfdQ/SCh9TxpJ8xM0gV+7bLI/2/bhvyBy2t5wN8nE0BvhDHqexqb2uOgcbG
# fR01Xf3wfPUhsP9P5gx6kEtbTOu/p+alng0SIGJbMh8IEikqTpE7vXKZAgMBAAGj
# ggGcMIIBmDAgBgNVHSUEGTAXBggrBgEFBQcDAwYLKwYBBAGCN0w3AQEwHQYDVR0O
# BBYEFHXvI7qCMN5A9CA67E5+euuA7osXMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ1ODIwNCs1MDIzNjgw
# HwYDVR0jBBgwFoAUoH7qzmTrA0eRsqGw6GOA4/ZOZaEwaAYDVR0fBGEwXzBdoFug
# WYZXaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvV2luZG93cyUy
# MEludGVybmFsJTIwQnVpbGQlMjBUb29scyUyMFBDQSUyMDIwMjAuY3JsMHUGCCsG
# AQUFBwEBBGkwZzBlBggrBgEFBQcwAoZZaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9XaW5kb3dzJTIwSW50ZXJuYWwlMjBCdWlsZCUyMFRvb2xz
# JTIwUENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAgQ1dOCwKwdC7GiZd++nSi3Zf0JFdql5djuONH/K1eYBkr8gmTJRcA+vCjNPa
# JdDOglcMjNb9v7TmfSfwoxq1MILay5t+W4QmlR+C7fIDTLZik/XSml+flbBiOjmk
# eEADJkhHpqU5aIxQZ89fa5fgrzyexW5XFSCCJSUOJCp/TujNu6m9RWG7ugsN2KPZ
# uF0aj5gUAmQQaUeRK7GZd9EHO9DKDUMl3ZbNAmcnKaV1jRQcrt4To6GGSLiCc1lp
# b5LrZnYdmiwGpLzBVGnrhK7z6vbyuhuUkO9HRwFWokeRGcwsCwXon/1woxsWWrR1
# V9b+1Wib/ZifdaprivedWI288rJyd5n7k0v+UYdj3HjoZUWovMnr7m5zmwHohJ/2
# P8uLU8aYIjb7olTDU5dbfopa2og6B+Ijq2Y1N0hc7uM+VY3wJcYp4bJF3gGxRmK2
# 1fDN592NWfjk2lKtB0tZ38LREVLcf4k7J3ENzjuamEgWkmECPvYtTuTdr+v4sgaA
# X37RdZB6zTsF2K5mXhlonscMNU4ThKCIM/aTfVAIaOPhSXwiHnEqZzqoFYYCl5k8
# LHY/JbUDfXROnAABXDVgDkSfPMpg0qYXDflrOO0I0ehKTg3g+D8X5C1La6+d3cuP
# 3C/DI/0zSVzaqawAATXWHcxlH/R8F2N/3Xn0sk4HlvoES28wggctMIIFFaADAgEC
# AhMzAAAAVlq1acsdlGgsAAAAAABWMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBT
# ZXJ2aWNlcyBQYXJ0bmVyIFJvb3QwHhcNMjAwMjA1MjIzNDEyWhcNMzUwMjA1MjI0
# NDEyWjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwG
# A1UEAxMlV2luZG93cyBJbnRlcm5hbCBCdWlsZCBUb29scyBQQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJeO8Bi8BZ0LmiWJmxhr8XqilrM9
# 8Le3i6/bgnolF1sE2w8obZr5HmO8FnkT+2TPpVMWsvnz8NaybPtns+i1a3lX+F85
# uM2pX+kBnaUPjRNZ4Nr4eYZeTNsu+fvJkkuFg1dcQqRypLdSbpSz4NSb6rjFxF7i
# Z2A7JnhVaR2eKSmFMCNH8fLz10ORthw/YwS1xvw/Lm5TU+YSRQWfydS+wgfMPapg
# oXtrOp28UH+HXoySBu0uQYC6azrB/eTPNiDQO4TlAJdWzV4yvLSpEKIVisUZTAQL
# cE9wVumQQvG8HKIF3v5hr+U/5aDEOJaqlNPqff99mYSuajKHQWPV4wJUHMohX93j
# nz7HhtJLhf/UeVglNcKayiiTI0NcCJbyPxD1/nCy2F3wnTmrF43lHJHHeNIunrNI
# sI6OhbELkWIZiVp83Dt9/5db2ULbdf564qRZAO2VUlvD0dFA1Ii9GZbqSThenYsY
# 0gnmZ1QIMJVJIt0zPUY1E0W+n/zkEedBM+jbaBw6De+zBNxTjpDg3qf1nRibmXGW
# SXv3uvyqzW+EnAozTUdr1LCCbsQTlEH+gzHG9nQy4zl1gTbbPMF77Lokxhueg/kr
# sHlsSGDI/GIBYu4fVvlU6uzAfahuQaFnIj5WHNkN6qwIFDFmNvpPRk+yOoMLAAm9
# XHKK1BxyOKixu/VTAgMBAAGjggGbMIIBlzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFKB+6s5k6wNHkbKhsOhjgOP2TmWhMFQGA1Ud
# IARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSNuOM2u9Xe
# l8uvDk17vlofCBv6BjBRBgNVHR8ESjBIMEagRKBChkBodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3Js
# MF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3J0
# MA0GCSqGSIb3DQEBDAUAA4ICAQBhSN9+w4ld9lyw3LwLhTlDV2sWMjpAjfOdbLFa
# tPpsSjVGHLBrfL+Y97dUfqCYNMYS5ByP41eRtKvrkby60pPxDjow8L/3tOVZmENd
# BU3vn28f7wCNy5gilO444fz4cBbUUQHnc94nMsODly3N6ohm5gGq7p0h9klLX/l5
# hbe2Rxl5UsJo3EuK8yqP7xz7thbL4QosQNsKiEFM91o8Q/Frdt+/gni6OTWVjCNM
# YHVB4CWttzJyvP8A1IzH0HEBG95Rdd9HMeudsYOHRuM4A0elUvRqOnsfqP7Zs46X
# NtBogW/IacvPGeuy3AHXIgMfFk35P9Mrt/ipDuqPy07faWLr0d+2++fWGv0yMSEf
# 0VWsMIYUK7fnmO+WK2j74KO/hFj3c+G/psecslWdT6zpeLntMB0IkqxN+Gw+qzc9
# 1vol2TEMHP2pITosnXYt33nZ9XR9YQmvMHBxwcF6qUALem5nOYMu574bCK6iOJdF
# SMfaUiLGppk7LOID0saA965KSWyxcpsxgvGnovjeUV1rJkN/NyPI3m5+t5w0v54J
# V2iCjgnsuF90m0cb2E3UUdEsbC6gBppQ/038OBoWMeVcd2ppmwP5O5vL5s4fCUp5
# p/og24gdqwrLJMZ+dHYVf3MsRqm7Lx3OVuxTuqbguRui+FdJtoBR/dMGFCWho1JE
# 8Qud9TGCGjkwgho1AgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACWMn7YqGMfm5AAAAAAAJMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD8SN5ZH8JLnhkvuim9YG2xu/TUFwvy
# KI/HTljJiLTJvzBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAmmsACOjCej+j
# X09Pg+8G5UbTm1lyrDdoOmRvrSvIGTypoYW9WA5zyB6QOMg1fQ1dB+wQF4HMK01b
# D1FsNCwoPtfTmV8vO63/rApbWe6FLJD+0JXsIeOX/fU9mkFt30jwhfYAykgp/KIa
# dOWYsRIgmTiVzq1Tgllboi2hWOazK+7Uqipftwj5wUrUS7dz3m4nD+OV1pTqZ9Nc
# 8udpftqzGeFdLWNkxmCBDqe4K0Ss8KJbSvk6T4VtCyWiO7PMRmzP9D5WjKv2Wsma
# NwxbzYmNMagZ6aU/BHnO7glNNaDs7WumusfAYcjsbUkt82UlgK87T0umsT7Zb/tZ
# ghMiVB+7B6GCF5YwgheSBgorBgEEAYI3AwMBMYIXgjCCF34GCSqGSIb3DQEHAqCC
# F28wghdrAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAE
# ggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCgMpXHmQk1
# QRHEClPJJun81zEeSIJepVX4OUEqX1bReQIGZ7euyK/sGBIyMDI1MDMxMDA4MTUz
# MC45NFowBIACAfSggdGkgc4wgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpGMDAyLTA1RTAtRDk0NzElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEe0wggcgMIIFCKADAgEC
# AhMzAAACBTx1bIJEh83+AAEAAAIFMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMB4XDTI1MDEzMDE5NDI0OVoXDTI2MDQyMjE5NDI0
# OVowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjpGMDAyLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AJKS8t93uAXWvbAZ3LzkIVhcdQLzLATIPgtEu/RZgRd55nS7li4runZxdXNCZk84
# dM3xNaobZI+VRv7s+V3MUMMCVHe9TymI6OaG72sdbjczZ1uiv2OX2CW6HPBR3ZJy
# JUZrt/23ru0zcoUpFIxcW0coXcrAEHtpWj5vWrLmn0NaWjY3kUasGocwRWU3LOt4
# digMsv6bx9Kyoy7+JhSrHMrkXhLshjk16YAHwH4DdCDBUiLrgokh94plR6JYoJN/
# ih1SA/cBCKXGHjw/rPsBPggDR0wS0qFgsWzhb8o0MyxivsqlA8pUJwLkTy4Md0p7
# C5vLN6eRPHLh9/U3eDzKGjk+L0F+NHRXK2uSakN96nwk/BxvgE04hc6jWl90dnwS
# +dHskVkVCKqkxkWU7kIC5Ngfy6Nzk9QeVowAnw0Rr1MUlM5IGsHs9GB6H/o0nbG7
# 3LE+H+RU30Eayz3cwLpSOmjF4zjHvRvBvCIrxI0cg7wPxyqXtVJ69RhuM3g2iAUX
# CEEKWGh0T/N4Y+rrLqLEPjPrkgdjfPAVBsFVf/D4v9Uc2f8EwazY8YeeVGM78qTw
# 0ik3iyGQVCoDV8zTx+usNI0Rj1UoO2mxSkAXnVjWhDq0mFYzV3ed4JeHpv/o35d4
# c5ELCdjzcr6kUwyGDyKxdBvopGXrmSDxdgF3gnCRsqhVAgMBAAGjggFJMIIBRTAd
# BgNVHQ4EFgQUdHpauzbtvr7IndsRn2jk10vVsvAwHwYDVR0jBBgwFoAUn6cVXQBe
# Yl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBD
# QSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADAWBgNV
# HSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQEL
# BQADggIBAA67GTjtvWLvlXzVPHrGjXTE0ivjNnFhV+QXlMWraSd08eDNXIueyzD8
# cqQRlEKBlWmQoQnpjiO8bm26AyL5aO3uFQxKKmT5GkHmAVC+HXGYAQvZ+V6DNNYS
# yePTCsRKmUjlne+B/Z4ZcCv9FyoaNKmi4dsPYdj1jcXQ6XoVEMJX8cQYpEfOfYzm
# tCkUZKNpxPgOSpViZ6b8Cs59K9WiOcoQhb3XhTEa26ElKv2M6jlGpNfsYipu283v
# OFaV36LdfF2F01x+VDP1iGgWpB7EF6eghGAA8C3AfrzFzOv0swLeX0AsSmey87RG
# Io9cXiXbb859wV99qmGeX9MPCSIl/E7IAx9QXfEj37eLNPVZfYIWzZFo4Crd1yiH
# InD7FEbQTzCQIeqRXnsFtQETMtfwv2UYnUOjFg2mgNfuJDMn1B2TKmLl+/vvcTcK
# HwD62jF4WnoWJ9BnIJzwhwgGUfJqToxtPphNVA2BD+HwUX5Lk6o/sIQIW8gfYq3Y
# /QaU670LQF9qyGdOOh2a1kVmym1S+KuT/Yc4suMGIyMPAmxAAUDMm7Phm1PKiuu8
# RHXQaX+ZuZWIeqG80AJ9PM+It+MODK+n2zv9se78JqUqZ6IlQsaOH+XACPnfX2mC
# CwYmpuEngVsVz6hTnN99ub+sqNVnyTE0PeKbXRCnjWfa3+qnI/oRMIIHcTCCBVmg
# AwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
# b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgy
# MjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ck
# eb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+
# uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4
# bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhi
# JdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD
# 4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKN
# iOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXf
# tnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8
# P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMY
# ctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9
# stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUe
# h17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQID
# AQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4E
# FgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9
# AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38
# Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTlt
# uw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99q
# b74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQ
# JL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1
# ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP
# 9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkk
# vnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFH
# qfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g7
# 5LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr
# 4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghi
# f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCA1AwggI4AgEBMIH5oYHRpIHO
# MIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQL
# ExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046RjAwMi0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVANWwf2nW0mf6SvAIy+o6FW9e
# tt60oIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZI
# hvcNAQELBQACBQDreJWaMCIYDzIwMjUwMzA5MjIzMjU4WhgPMjAyNTAzMTAyMjMy
# NThaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAOt4lZoCAQAwCgIBAAICMKYCAf8w
# BwIBAAICEnowCgIFAOt55xoCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGE
# WQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEA
# ThU3vNNF14vKZhxrkFk+rC8ze2P8AYbw+2UWR797RgOorHJqmb0kkLmHp6zv0o7h
# eVqg99wlk6CMB/3LxGtDyQK12Az4ZpCMRypONudM644yqN1ZSgX+MLLPzZp8DcGx
# U0vkfFh+vjwNfcWPJ4nIF9MzDmtAqvZjoiXZCKezwQsNJGDOlSAONmJFaB2Nzilm
# 0ssN6rAPrS4NpbDjGyIdYyRIJAZbW+oTbgUVfqkFh+9twM19AafgobViONtbRhWi
# sedUdTOqefi7algRbHzxWzTC73hjLj+buQSxr/TfI9oWRVdxoSK2QA5v8ZPHjL1h
# nxiV1XALZ4cMwX0/B54bCDGCBA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAACBTx1bIJEh83+AAEAAAIFMA0GCWCGSAFlAwQCAQUA
# oIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIE
# IPu4olPeVbhtr8zEgmCcmCxjDwuG8RhCWTpdHeu/3JCHMIH6BgsqhkiG9w0BCRAC
# LzGB6jCB5zCB5DCBvQQggA0DPdx5jS6aF1YtHawmmrQ4+q0kNMBhGaMdWTARb0gw
# gZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYw
# JAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAgU8dWyC
# RIfN/gABAAACBTAiBCA9e02yjI2Br8XhIA/b3Vsi7Bf4KJVC9tfbKozFEs7SBjAN
# BgkqhkiG9w0BAQsFAASCAgANJZS4h51+3acYUDTskcJ1nveSGBxkQnFM1uJOS7Uq
# 7jTf+63tf4T+BFp0s1TY9avg2rXRCrdLibWrS1sprEWkAmeGKQu1OaXKNl9TVhJn
# XBFPTRnxpYYSyE6EpXmRPoNY+hwTCl0BbVCOCiyTxyAbojcV0nmoxuJ+EmrfDfr7
# GTm4uh2g/NFB44DfFGqC5FDJCeOgf5+X3rWuna9Uc6jONywfXZPH4qt9DRHYfbSK
# aVZqLFpx/LAYhKwv5tJ2kP3AkFK1akpU2KiYekA7sIbgz2YWf2fSilN8NpOs6uxr
# Lx67zi/xTW/nB85NaYqSvOi+O0AXYau9bmsAv580CtnStowCY96yu+aC97Tb5klS
# izpZsrqLg3DfaPse7AcEFJjw+0JxtFm6bCLHqKaqDPOHOwN0VQfCHzNgq8UtLUe4
# xUkt2cdchmADicyPbfDi6H+VmHTN/D/PLFMRirju2+5/gPrt+DqNf17RHQWjS2TF
# kBAhznGNcunVZkmXSJ4a5wOUx4SAOCVySOqEDk8yU/1satZiwV5YiBVoMM7cktFF
# 7rQQmDvKWU2G+kCquLG8yBLji9ftUmjvc0VhHH90MQtJcxAr2mew365AZcpGqGnk
# fL/tlcndX18PR8JhWqqrD5Lgg50ppsbxfioLRDN7bPybh2JEcmzvcrcRVnyJlS0T
# rg==
# SIG # End signature block
