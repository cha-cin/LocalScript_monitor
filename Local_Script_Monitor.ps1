#  [void] [Reflection.Assembly]::Load("micron.security.net, Version=4.0.0.0, Culture=neutral, PublicKeyToken=2d8c82d3a1452ef1");
#  [Void][System.Reflection.Assembly]::LoadFile("C:\mu\Mtdev\gac64\micron.security.net\4.0.0.0\micron.security.net.dll");
#  
#  $dat_system='BE_ACCOUNTS_SHARED_WORLDWIDE'
#  $dat_version='beapps'
#  $dat_environment='PROD'
#  $siteName='TAICHUNG_BE'
#  $dat_servicename='beapps'
#  
#  
#  $myContext = new-object Micron.Application.Context($dat_system, $dat_version, $dat_environment, $siteName) -ErrorAction Stop
#  $myCredential = new-object Micron.Data.Credential($myContext, $dat_servicename) -ErrorAction Stop



#  $loginUser = $myCredential.UserID
#  $logingPwd = $myCredential.Password



$loginUser = 'winntdom\tbbeapps'
$logingPwd = 'Appsbackend1$PNmfgIT0123456789'
$csvPath = "C:\Users\lichiasin\Documents\Project\LocalScript_monitor\AppList2.csv"
$LogPath = "C:\Users\lichiasin\Documents\Project\LocalScript_monitor\"






# $password = ConvertTo-SecureString $logingPwd -AsPlainText -Force
# $psCred = New-Object System.Management.Automation.PSCredential ($loginUser, $password);
# $s = New-PSSession -ComputerName tbwmesm03 -Credential $psCred


#################################################
# # Get ScriptHostName as localhost if Host Parameter is not passed
# # $ScriptHostName indicates that who is running this script
#################################################



function LogMessage
{
    param([string]$Message)
    $Time = Get-Date -UFormat "%Y-%m-%d %H:%M:%S".ToString()

    ($Time + " - " + $Message) >> $LogFile;

}

function TurnOn_Task
{
    param([string]$Task)
    Write-Output($Task)
    Enable-ScheduledTask -TaskName $Task
}

if ([string]::IsNullOrEmpty($ScriptHostName)) {
    try {
        $ScriptHostName = [System.Net.Dns]::GetHostName().ToLower()
    }
    catch {
        $ErrorMessage = $_.Exception.Message

        # Write-Debug ("Exception: {0}" -f $ErrorMessage)
        LogMessage -Message $ErrorMessage;
        $Global:ReturnStatus = "Fail"
        $Global:ReturnMessage = "Failed to get Host name"
        return
    }
}
else {
    $ScriptHostName = $ScriptHostName.ToLower()
}

# #################
# Write Log Setting
# #################



$Date = Get-Date -UFormat "%Y%m%d".ToString()
$Drive = "\c"
$HostName = $ScriptHostName
# 定義logfile
$LogFile = $LogPath + $ScriptHostName + "-Local_Script_Monitor-" + $Date.ToString() + ".trc"


LogMessage -Message "########################### Beginning of this script ###########################";
LogMessage -Message "Targeted host name: $HostName";






# 開始讀檔(Cronjon Config)
try{ 
    LogMessage -Message "Trying to load the list of applcations monitored ... ";
    $csv = Import-Csv $csvPath
    $application = $csv.AppName
    # $application
    LogMessage -Message "=== $($csv.AppName.count) of the cronjob(applications) found:  ===";
    LogMessage -Message $csv.AppName;
    LogMessage -Message "============================";
}
catch {
    $ErrorMessage = $_.Exception.Message
    Write-Debug ("Exception: {0}" -f $ErrorMessage)
    LogMessage -Message "Failed to load the applcation list ... ";
    LogMessage -Message $ErrorMessage;
    $Global:ReturnStatus = "Fail"
    $Global:ReturnMessage = "Failed to load the applcation list ... "
    return
}


# $cronjob = Get-ScheduledTask | where-object {$_.State -LIKE 'Ready'}
try{
    $cronjob = Get-ScheduledTask
}
catch{
    $ErrorMessage = $_.Exception.Message
    Write-Debug ("Exception: {0}" -f $ErrorMessage)
    LogMessage -Message "Failed to load the current applcation list of this server... ";
    LogMessage -Message $ErrorMessage;
    $Global:ReturnStatus = "Fail"
    $Global:ReturnMessage = "Failed to load the current applcation list of this server ... "
}
# $cronjob
LogMessage -Message "Trying to query the list of ScheduledTask which states is Ready"
# LogMessage -Message $cronjob;

foreach($config_job in $application){
   foreach ($current_job in $cronjob){
        if($current_job.TaskName -eq $config_job){
            # Write-Output($current_job.TaskName, $current_job.State)
            if(($current_job.State -ne "Ready") -and ($current_job.State -ne "Running")){
                # Write-Output($current_job.TaskName, $current_job.State)
                LogMessage -Message $current_job.TaskName
                LogMessage -Message "state is not Ready or Running currently."
                LogMessage -Message "Should be to turn on it."
                TurnOn_Task($current_job.TaskName)
                Start-Sleep -Seconds 2
            }
        }
   } 
}





# Invoke-Command -Session $s {
#    $cronjob = Get-ScheduledTask | where-object {$_.State -LIKE 'Ready'}
#    $cronjob.State
#    foreach ($a in $cronjob){
#       if ($a.State -eq "Ready"){
#          'YES'
#       }else {
#           'No'
#       }
#    }
# }








#Exit-PSSession






















# function Get-DATCredentials {
#     Param ([string] $dat_system, [string] $dat_version, [string] $dat_environment, [string] $dat_servicename, [string] $siteName)
#     $myContext = ''
#     $myCredential = ''
#     try {
#         #Write-Log -logstring "[Get-DATCredentials] Getting DAT Credential: System - $($dat_system)  Version - $($dat_version)  Env - $($dat_environment)  Service - $($dat_servicename)  Site - $($siteName)" -type "INFO" -lvl 4
#         $myContext = new-object Micron.Application.Context($dat_system, $dat_version, $dat_environment, $siteName) -ErrorAction Stop
#         $myCredential = new-object Micron.Data.Credential($myContext, $dat_servicename) -ErrorAction Stop
#         #Write-Log -logstring "`t Successfully obtained DAT Credential" -type "INFO" -lvl 4
#         return $myCredential
#     } catch {
#         #Write-Log -logstring "[Unable to get DAT Credentials]: $_" -type "ERROR" -lvl 1
#         Return
#     }
# }