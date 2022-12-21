


#<--------------------------- Manage Active Directory --------------------------->
Param([Parameter(Mandatory=$True,Position=1)][String]$DomainController,
    [Parameter(Mandatory=$True,Position=2)][String]$DomainExtension,
    [Parameter(Mandatory=$True,Position=3)][String]$Workstation,
    [Parameter(Mandatory=$True,Position=4)][String]$Server,
    [Parameter(Mandatory=$True,Position=5)][String]$OrganizationalUnit,
    [Parameter(Mandatory=$True,Position=6)][String]$PrimaryDomainController,
    [Parameter(Mandatory=$True,Position=7)][String]$Trust,
    [Parameter(Mandatory=$True,Position=8)][String]$FSMO)

$error.clear()

if (Get-Module -ListAvailable -Name activedirectory){
    
    Write-Output "Active Directory module has been loaded."

    try{

        gpupdate /force
        gpupdate /sync

        Write-Output "Attempting to check users created within the past 90 days."
        Get-QADUser -CreatedAfter (GET-Date).AddDays(-90)

    }catch{

        Write-Output "Error attempting to check users created within the past 90 days!!"

    }
    if($error){

        Write-Output "Attemtping to check users created within the past 90 days using another method."
        Get-ADUser -Filter * -Properties whenCreated | 
            Where-Object {
                $_.whenCreated -ge ((Get-Date).AddDays(-90)).Date
                }
        $error.clear()

    }

}else{

    Import-Module activedirectory
    gpupdate /force
    gpupdate /sync
    Get-QADUser -CreatedAfter (Get-Date).AddDays(-90)


}

#<--------------------------- Check for Remote Admin Tools --------------------------->
Write-Output "Checking for Remote Admin Tools"
Get-WinEvent -FilterHashTable @{ 
    Logname='System'; 
    ID='7045'
    } | where {
        $_.Message.contains("PSEXEC")
        }
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLIne_Enabled /t REG_DWORD /d 1

#<--------------------------- Check for Persistance --------------------------->
$tasks = Get-ChildItem -recurse -Path "C:\Windows\System32\Tasks" -File

foreach ($task in $tasks){

    $taskInfo = "" | select ComputerName, Task, User, Enabled, Application
    $taskD = [xml](Get-Content $task.FullName)
    $taskList = New-Object -TypeName psObject
    $taskList | Add-Member -MemberType NoteProperty -Name TaskName -Value $task.Name
    $taskList | Add-Member -MemberType NoteProperty -Name User -Value $taskD.Task.Principals.Principal.UserId
    $taskList | Add-Member -MemberType NoteProperty -Name Enabled -Value $taskD.Task.Settings.Enabled
    $taskList | Add-Member -MemberType NoteProperty -Name Command -Value $taskD.Task.Actions.Exec.Command $taskList

}

# Enforce Safe DLL Search Mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1

# Disable RunOnce
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisableLocalMachineRunOnce /t REG_DWORD /d 1

# Detect Alternate Data Stream
Get-ChildItem -recurse -path C:\ | 
    where {
        Get-Item $_FullName -stream *
        } | 
        where stream -ne ':$Data'

# Detect Virtual Machines on Network
Get-ADComputer -filter {operatingSystem -like "Windows Server*"} | 
    Select-Object name | 
        Export-CSV .\adComputers.txt -notypeinformation -encoding UTF8 (
            Get-Content .\adComputers.txt) | 
                % {
                    $_ -replace '"',""
                    } | Out-File -FilePath .\adComputers.txt -force -encoding ascii $Computers=(
                            Get-Content .\adComputers.txt) | 
                                Select -Skip 1 foreach($Computer in $Computers) 
                                {
                                    systeminfo /s $computer | 
                                        findstr /c:"Model:" /c:"Host Name" /c:"OS Name" | 
                                            Out-File -FilePath .\vmdet.txt -append
                                }

# Detect C&C
$l = @()
.\tshark.exe -i Ethernet0 -T ek -e ip.src -e ip.dst 2>$null |
    % {
        $t=(ConvertFrom-Json $_).layers;
        if($t.ip_src){
            $l+=$t.ip_src[0];
            $l+=$t.ip_dst[0]
            }
        }; $l |
            Sort-Object -Unique | 
                Out-File ~/c2-ip-list.txt

#Enable DNS Logging
$logName = 'Microsoft-Windows-DNS-Client/Operational'
$log= New-ObjectSystem.Diagnostics.Eventing.Reader.EventLogConfiguration $logName$log.IsEnabled=$True
$log.SavChanges()

#Detect Alternate Data Stream
Get-ChildItem -recurse -path C:\ |
    where {
        Get-Item $_.FullName -stream *
        } | 
        where stream -ne ':$Data'

