function Get-LogonLocations
{
<#
.SYNOPSIS

This script will search the Security Event Log on specified computers for 4624 logon events from specified user(s).

Function: Get-LogonLocations
Author: Josh M. Bryant
Required Dependencies: Active Directory Module
Optional Dependencies: None
Version: 1.2
Last Updated: 4/25/2016 12:35 PM CST

.DESCRIPTION

Lists unique logon entries found for the specified user(s)

.PARAMETER Users

Specify one or more users to search for logons from. Must use SAMAccountName, separate multiple users with a comma.

.PARAMETER Groups

Specify one or more groups to recursively enumerate membership and searches for logons from all user members. Must use SAMAccountName, separate multiple groups with a comma.

.PARAMETER ComputerName

Specify the name of the computer to search for logon events on. If not specified all Domain Controllers are searched.

.PARAMETER EventLog

Specify the name of the EventLog to search for logon events. If not specified, the Security log is searched.

.PARAMETER Tier0

Switch. Default if the Users or Groups parameters are not specified. Recursively enumerates membership of Tier 0 groups based on the list at http://aka.ms/tier0 and searches for logons from user members.

.EXAMPLE

Get-LogonLocations -Users Admin1,Admin2

Searches for logons from Admin1 and Admin2 and outputs to the screen in list format.

.EXAMPLE

Get-LogonLocations -Groups "Organization Management","Server Admins" | FT

Recursively enumerates membership of the "Organization Management" and "Server Admins" groups and searches for logons from users that are a member of the specified gorups,
as well as any nested groups, then outputs to the screen in table format.

.EXAMPLE

Get-LogonLocations -ComputerName WEF01 -EventLog ForwardedEvents -Users BadGuy

Searches the "ForwardedEvents" Event Log on the computer "WEF01" for logons from the user "BadGuy"

.EXAMPLE

Get-LogonLocations | Sort-Object User,ComputerName,IPAddress

Recursively enumerates membership of Tier 0 groups based on the list from http://aka.ms/tier0 and searches for logons users that are a member of the Tier 0 groups,
as well as any nested groups, then outputs only entries that have a unique combination of User, ComputerName, and IPAddress.

.EXAMPLE

Get-LogonLocations | Export-CSV LogonLocations.csv -NoType

Recursively enumerates membership of Tier 0 groups based on the list from http://aka.ms/tier0 and searches for logons users that are a member of the Tier 0 groups,
as well as any nested groups, then outputs to a CSV file.

.NOTES

This script was written to help automate discovery of privileged accounts, but may have other uses.

.LINK

Blog: http://www.fixtheexchange.com

#>

    [CmdletBinding(DefaultParameterSetName="Tier0")]
    param (
        [Parameter(
            ParameterSetName="Main")]
            [array]$Users,
            [array]$Groups,
            [array]$ComputerName,
            [string]$EventLog,
        [Parameter(
            ParameterSetName="Tier0")]
            [switch]$Tier0
    )

$LogName = "Security"
$Domains = (Get-ADForest).Domains
$RootDomain = (Get-ADForest).RootDomain
$GlobalCatalog = ((Get-ADDomainController -Discover -Domain $RootDomain -Service "GlobalCatalog" -MinimumDirectoryServiceVersion Windows2008).HostName -join ("")) + ":3268"
$RootDomainSID = ((Get-ADForest).RootDomain | Get-ADDomain).DomainSid.Value

#Builtin Tier 0 Group SIDs
$AccountOperatorsSID = "S-1-5-32-548"
$AdministratorsSID = "S-1-5-32-544"
$BackupOperatorsSID = "S-1-5-32-551"
$CryptographicOperatorsSID = "S-1-5-32-569"
$PrintOperatorsSID = "S-1-5-32-550"
$ServerOperatorsSID = "S-1-5-32-549"

#Root Domain Tier 0 SIDs
$EnterpriseAdminsSID = $RootDomainSID + "-519"
$SchemaAdminsSID = $RootDomainSID + "-518"

$Tier0Groups = $AccountOperatorsSID,$AdministratorsSID,$BackupOperatorsSID,$CryptographicOperatorsSID,$EnterpriseAdminsSID,$PrintOperatorsSID,$SchemaAdminsSID,$ServerOperatorsSID

#Per Domain Tier 0 SIDs
$DomainAdminSIDs = @()
$DomainControllersSIDs = @()
$GroupPolicyCreatorOwnersSIDs = @()
$ReadOnlyDomainControllersSIDs = @()
ForEach ($Domain in $Domains) {
    $DomainControllers += (Get-ADDomain $Domain).ReplicaDirectoryServers
    $DomainSID = (Get-ADDomain $Domain).DomainSID.Value
    $DomainAdminSID = $DomainSID + "-512"
    $DomainControllersSID = $DomainSID + "-516"
    $GroupPolicyCreatorOwnersSID = $DomainSID + "-520"
    $ReadOnlyDomainControllersSID = $DomainSID + "-521"
    $Tier0Groups = $Tier0Groups + $DomainAdminSID + $DomainControllersSID + $GroupPolicyCreatorOwnersSID + $ReadOnlyDomainControllersSID
}

If ($PSCMdlet.ParameterSetName -eq "Tier0" -and $PSBoundParameters.Keys -notcontains "Tier0") {
    $input = $PSCMdlet.ParameterSetName
} Else {
    $input = $PSBoundParameters.Keys
}

switch ($input) {
    "Users" {
        $Usernames = $Users | Select -Unique
    }
    "Groups" {     
        ForEach ($Domain in $Domains) {
            $DC = (Get-ADDomainController -Discover -Domain $Domain -MinimumDirectoryServiceVersion Windows2008 ).hostname -join ("")
            ForEach ($Group in $Groups) {
                $Users = $Users + (Get-ADGroupMember $Group -Recursive -Server $DC | Where {$_.objectClass -eq "user"})
            }
        }
        $Usernames = $Users | Select -ExpandProperty SAMAccountName -Unique
    }
    "ComputerName" {
        $DomainControllers = $ComputerName
    }
    "EventLog" {
        $LogName = $EventLog
    }
    "Tier0" {
        ForEach ($Domain in $Domains) {
            $DomainSID = (Get-ADDomain $Domain).DomainSID.Value
            $DC = (Get-ADDomainController -Discover -Domain $Domain -MinimumDirectoryServiceVersion Windows2008 ).hostname -join ("")
            ForEach ($Tier0Group in $Tier0Groups) {
                If ($Tier0Group -like "S-1-5-32-*" -or $Tier0Group -match $DomainSID) {
                    $Users = $Users + (Get-ADGroupMember $Tier0Group -Recursive -Server $DC -ErrorAction SilentlyContinue | Where {$_.objectClass -eq "user"})
                }    
            }
         }
        $Usernames = $Users | Select -ExpandProperty SAMAccountName -Unique
    }
}

$ReturnInfo = @()
$DCProgress = $null
ForEach ($DomainController in $DomainControllers) {
    $DCName = $DomainController
    $Events = $null
    $UserProgress = $null
    $DCProgress++
    If ($PSVersionTable.PSVersion.Major -ge 3) {
        Write-Progress "$DCName" -PercentComplete (($DCProgress / $DomainControllers.Count) * 100)
    }
    Try {
        ForEach ($Username in $Usernames) {
            $UserProgress++
            If ($PSVersionTable.PSVersion.Major -ge 3) {
                Write-Progress -Activity "$DCName" -Status "Searching..." -CurrentOperation "Looking for logons from $Username." -PercentComplete (($UserProgress / $Usernames.Count) * 100)
            }
                $Events = Get-WinEvent -LogName $LogName -ComputerName $DCName -FilterXPath @"
                *[
                    System[EventID=4624] and
                    EventData[Data[@Name='TargetUserName']='$Username'] or
                    System[EventID=528] and
                    EventData[Data[@Name='TargetUserName']='$Username'] or
                    System[EventID=540] and
                    EventData[Data[@Name='TargetUserName']='$Username']
             ]
"@ -ErrorAction SilentlyContinue
            $EventsError = $error[0]
            If ($Events -eq $null -and $EventsError -match "No events were found that match the specified selection criteria.") {
                Write-Verbose "No logons for $Username found on $DCName"
                }
            If ($Events) {
                $EventProgress = $null
                ForEach ($Event in $Events) {
                    $NameResolution = $null
                    $EventProgress++
                    If ($PSVersionTable.PSVersion.Major -ge 3) {
                        Write-Progress -Activity "$DCName" -Status "Processing..." -CurrentOperation "Gathering logon data for $Username." -PercentComplete (($EventProgress / $Events.Count) * 100)
                    }
                    
                    [XML]$EventXML = $Event.ToXML()
                    $EventData = $EventXML.FirstChild.EventData
                    $EventSystem = $EventXML.FirstChild.System
                    $EventSystemProperties = @{}
                    $EventDataProperties = @{}
                    $EventData.GetEnumerator() | ForEach-Object { $EventDataProperties[$_.Name] = $_.'#text' }
                    $EventSystem.GetEnumerator() | ForEach-Object { $EventSystemProperties[$_.Name] = $_.'#text' }
                    $EventDataObject = New-Object PSObject -Property $EventDataProperties
                    $EventSystemObject = New-Object PSObject -Property $EventSystemProperties

                    $LogonTypeText = Switch ($EventDataObject.LogonType) {
                        2 {'Interactive'}
                        3 {'Network'}
                        4 {'Batch'}
                        5 {'Service'}
                        7 {'Unlock'}
                        8 {'NetworkCleartext'}
                        9 {'NewCredentials'}
                        10{'RemoteInteractive'}
                        11{'CachedInteractive'}
                    }
                    
                $IPAddress = $EventDataObject.IPAddress
 
                If ($EvendDataObject.WorkstationName -eq $null -and $IPAddress -ne "-") {
                    If ($IPAddress -eq "127.0.0.1" -or $IPAddress -eq "::1") {
                        $NameResolution = $EventSystemObject.Computer
                    } Else {

                Try {
 
                    $NameResolution = ([System.Net.DNS]::GetHostByAddress($IPAddress)).HostName
                    If ($NameResolution -eq $null -or $IPAddress -like "169.254.*") {
                        $NameResolution = "Unable to resolve"
                    }
                    If ($IPAddress -eq "0.0.0.0") {
                            Try {
                                $IPAddress = ([System.Net.DNS]::GetHostAddresses($NameResolution)).IPAddressToString | Where {$_.AddressFamily -notlike "InterNetworkV6"}
                            } Catch {
                                $IPAddress = "Unknown"
                            }
                    }
 
                }
                Catch { 
                    If ($EventDataObject.WorkstationName -ne $null) {
                        $NameResolution = $EventDataObject.WorkstationName
                        If ($IPAddress -eq "0.0.0.0") {
                            Try {
                                $IPAddress = ([System.Net.DNS]::GetHostAddresses($NameResolution)).IPAddressToString
                            } Catch {
                                $IPAddress = "Unknown"
                            }
                            
                        }
                    } Else {
                        $NameResolution = "Unable to resolve"
                    }
                }

                    }
                } ElseIf ($EventDataObject.WorkstationName -ne $null -and $IPaddress -eq "-" -or $EventDataObject.WorkstationName -ne $null -and $IPAddress -eq "0.0.0.0") {
                    $NameResolution = $EventDataObject.WorkStationName
                    Try {
                        $IPAddress = ([System.Net.DNS]::GetHostAddresses($NameResolution)).IPAddressToString 
                        If ($IPAddress -eq $null -or $IPAddress -eq "-") {
                            $IPAddress = "Unknown"
                        }
                        } Catch {
                            If ($IPAddress -eq $null -or $IPAddress -eq "-") {
                                $IPAddress = "Unknown"
                            }
                        }

                        
                }
 
            $Properties = @{
                "User" = $EventDataObject.TargetUserName
                "Domain" = $EventDataObject.TargetDomainName
                "EventSource" = $EventSystemObject.Computer
                "IPAddress" = $IPAddress
                "ComputerName" = $NameResolution
                "LogonTime" = $Event.TimeCreated
                "LogonType" = $EventDataObject.LogonType
                "LogonTypeText" = $LogonTypeText
                "EventData" = $Event.Message
            }
            $Item = New-Object PSObject -Property $Properties
            $ReturnInfo = $ReturnInfo + $Item
        }
    }

        }
    } Catch {
        $EventsError = $error[0]
        If ($EventsError -match "The RPC server is unavailable" -or $EventsError -match "There are no more endpoints available from the endpoint mapper") {
            Write-Warning "Unable to read Security log on $DCName, please ensure $DCName is powered on, and that no firewalls are blocking access to $DCName."
            }
      }

If ($PSVersionTable.PSVersion.Major -ge 3) {
    Write-Progress -Activity "$DCName" -Completed
}

}

Return $ReturnInfo | Select User,Domain,ComputerName,IPAddress,LogonTime,LogonType,LogonTypeText,EventSource,EventData | Where {$_.ComputerName -ne $null -and $IPAddress -ne "-"}

}
