
$csvPath = "C:\AutoRecovery\AppList.csv"
$LogPath = "C:\MTApps\AutoRecovery\trace\"

$LogPath

$debugMode = 0
## CheckMultDispatchMgr = 1, this script will check if the DispatchMgr and DispatchPMgr are in the same server.
$CheckMultDispatchMgr = 1

$exceptionCheck = 1

$logTraceCheck = 1 ## if = 1. this script will monitor the trace log last update datetime, 
$LastUpdatedThres = 180 # if the latest file doesn't update over LastUpdatedThres (Minutes), it is considered a failedapp.


$turnOnRecovery = 1;

## Exception check range (in minute), the value sholud be negative.
## i.e (if periodRangeTime = -5), it will check the windows evnets during now and 5 minute ago
$periodRangeTime = -5


function LogMessage
{
    param([string]$Message)

    $Time = Get-Date -UFormat "%Y-%m-%d %H:%M:%S".ToString()

    ($Time + " - " + $Message) >> $LogFile;

}

#################################################
# # Get ScriptHostName as localhost if Host Parameter is not passed
# # $ScriptHostName indicates that who is running this script
#################################################
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


$LogFile = $LogPath + $ScriptHostName + "-detectApp-" + $Date.ToString() + ".trc"

Write-Debug ('{0}' -f $LogFile)

$HostName = $ScriptHostName

LogMessage -Message "########################### Beginning of this script ###########################";
LogMessage -Message "Targeted host name: $HostName";


# ######################################################
# Load the csv file and try to get the service(applications) which is going to be 
# monitored in this host.
# ######################################################

try{ 
    LogMessage -Message "Trying to load the list of applcations monitored ... ";
    $csv = Import-Csv $csvPath
    $ProcessesToCheckFor = $csv.AppName
    $countAppAmount =  $csv.AppName.count


    LogMessage -Message "=== $($csv.AppName.count) of the services(applications) found:  ===";
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

# ## 

function SendEmail {

    param (


         [Parameter(Mandatory=$true, Position=0)]
         [string] $EmailTo,
         [Parameter(Mandatory=$true, Position=1)]
         [string] $Subject,
         [Parameter(Mandatory=$true, Position=2)]
         [string] $Body


        # [string]$EmailTo
        # [string]$Subject
        # [string]$Body
    )




    $EmailFrom = "TBMES@micron.com"
    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

    try { 

       
        $SMTPServer = "exchange.micron.com" 
        $SMTPMessage = New-Object System.Net.Mail.MailMessage($EmailFrom,$EmailTo,$Subject,$Body)
        $SMTPClient = New-Object Net.Mail.SmtpClient($SmtpServer)
        $SMTPClient.Send($SMTPMessage)
              

    }

    catch [Exception] {
        Write-Host $_.Exception;
            
    }
    
}






if ($CheckMultDispatchMgr -eq 1){

    LogMessage -Message "Start checking if the DispatchMgr and DispatchPMgr are in the same server.";
    "Start checking if the DispatchMgr and DispatchPMgr are in the same server."

    $MgrCommandLine="P:\SOFTWARE\Dispatch\automation\DispatchMgr.exe"
    $PMgrCommandLine="P:\SOFTWARE\Dispatch\automation\DispatchPMgr.exe"
    $MgrEscapePath = [regex]::escape($MgrCommandLine)
    $PMgrEscapePath = [regex]::escape($PMgrCommandLine)

    $Mgr = Get-WmiObject Win32_Process | where CommandLine -match $MgrEscapePath | Select-Object ProcessId, Name, Path, CommandLine
    $PMgr = Get-WmiObject Win32_Process | where CommandLine -match $PMgrEscapePath | Select-Object ProcessId, Name, Path, CommandLine

    if (![string]::IsNullOrEmpty($Mgr) -and ![string]::IsNullOrEmpty($PMgr)) {
        LogMessage -Message "<WARNING> the DispatchMgr and DispatchPMgr are in the same server!";
        "<WARNING> the DispatchMgr and DispatchPMgr are in the same server!"

        $emailBody = "
        [Trigger Criteria] the DispatchMgr and DispatchPMgr are in the same server `n
        [Impact] Might cause users get slow and wait for a long time to query the lots from BIMenu - Dispatch Client. 
        [ScriptInfo]`n
        LogFile: $($LogFile)
        HostName: $(HostName)
        [Action] Follow the Burn PM SOE to move the application manually. `n
        [SOE] onenote:///\\tasvmitdoc-88-lif1\OMT_IT\TEAM_MES\BACKEND\TeamOneNote\MTB_MES\PM%20Procedure.one#TBWBURNAPP&section-id={E261ABB5-B198-4A2B-B133-C14D79FCEF00}&page-id={5231D08A-993B-4288-87D6-7F28F7B43ECF}&end

        "
        SendEmail -EmailTo "IT_MFG_BE_OPS_MTB@micron.com" -Subject " [Alert] : DispatchMgr and DispatchPMgr are running in the same server!" -Body $emailBody




    }else {
        
        LogMessage -Message "<Trace> the DispatchMgr and DispatchPMgr";
        "<WARNING> the DispatchMgr and DispatchPMgr are in the same server!"

    }




}



# ## Check the AppList content if is empty, if yes, terminate the script.
if ($countAppAmount -eq 0){
    LogMessage -Message "There is no app listed on the AppList.csv file, exiting the script ... ";
    exit
}else {
    LogMessage -Message "Found app listed on the AppList.csv file, starting to inspect ... "; 
    
}



$applications = $ProcessesToCheckFor 
$failedApps = @()
$processList = New-Object System.Collections.Generic.List[System.Object]



LogMessage -Message "<DETECTING SCRIPT START>";        



####################################################                  
# # PID Detetion Start  
#################################################### 

$allItem = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, Path, CommandLine
$csv | ForEach-Object {

    "<TRACE> --------------- Inspecting pid for --------------- $($_.AppName)"


    LogMessage -Message "<TRACE> --------------- Inspecting pid for --------------- $($_.AppName)";

    # ## The way of detecting is to fetch the keyword of commandline, so, will read the folder path \{AppName} and compare to the appName of AppList.csv file
    # ## e.g. AppName: %BurnLotServer% which is include in commandLine: "C:\software\BurnLotServer\BrnLotSrv.exe"

    $curEscapePath = [regex]::escape($_.CommandLine)

    if ($_.AppName -like "%Tomcat%")
    {$curEscapePath = "Tomcat"}

    $item = Get-WmiObject Win32_Process | where CommandLine -match $curEscapePath | Select-Object ProcessId, Name, Path, CommandLine

    
    if (![string]::IsNullOrEmpty($item)) {

        "ProcessName=$($item.Name); PID=$($item.ProcessId); Path=$($item.Path); CommandLine=$($item.CommandLine);"
        LogMessage -Message "ProcessName=$($item.Name); PID=$($item.ProcessId); Path=$($item.Path); CommandLine=$($item.CommandLine);";



    }else{

        LogMessage -Message "<WARNING> Found a failed application!";
        "<WARNING> Found a failed application!"
        $thisFailedApp = $_.AppName
        $failedApps += $thisFailedApp.ToString();

    }



    "<TRACE> --------------- Inspecting trace log for --------------- $($_.AppName)" 
    LogMessage -Message  "<TRACE>  Inspecting trace log for $($_.AppName)";
    if ($logTraceCheck -eq 1 -and $_.LastUpdatedThres)
    {

        if ($_.TracePath -ne "NoLog"){

            "The trace path:  $($_.TracePath)"
            LogMessage -Message  "The trace path:  $($_.TracePath)";

            $latest = Get-ChildItem $_.TracePath -Attributes !Directory *.* | Sort-Object -Descending -Property LastWriteTime | select -First 1
            $latest.LastWriteTime

            $currentDateTime = Get-Date
            # $currentDateTime

            $diff= New-TimeSpan -Start $latest.LastWriteTime -End $currentDateTime 

            # $diff
            "<TRACE> The lastest files info: name: $($latest), last modified datetime:  $($latest.LastWriteTime) "
            LogMessage -Message "<TRACE> The lastest files info: name: $($latest), last modified datetime:  $($latest.LastWriteTime) ";

            if ($diff.TotalMinutes -gt $_.LastUpdatedThres){
                "<WARNING> The application trace log didn't update over $($_.LastUpdatedThres) minutes."
                LogMessage -Message  "<WARNING>  The application trace log didn't update over $($_.LastUpdatedThres) minutes.";



                $thisFailedApp = $_.AppName
                $failedApps += $thisFailedApp.ToString();



            }else {
                "<Trace> The application trace log update below $($_.LastUpdatedThres) minutes."
                LogMessage -Message  "<Trace> The application trace log update below $($_.LastUpdatedThres) minutes.";

            }
            

        }else {
            "There is no trace log for this application."
            LogMessage -Message  "There is no trace log for this application.";
        }
        

    }else {
        "Detection trace log alive function is disable"
        LogMessage -Message  "Detection trace log alive function is disable";
    }
    
    "<TRACE>  ---------------  Inspecting trace log end ---------------  " 
    LogMessage -Message  "---------------  <TRACE>  Inspecting trace log end --------------- ";






}



LogMessage -Message "<Detection End>";


####################################################                  
# # PID Detetion End  
#################################################### 

if ($exceptionCheck -eq 1)
{
    ####################################################                  
    # # Exception Detetion Start  
    #################################################### 
    LogMessage -Message "<TRACE> Exception Check - Start";
    LogMessage -Message "<TRACE>Start to check whether if it is running but actually failed";
    'start to check whether if it is running but actually failed'



    ##

    # $periodRange = (Get-Date).AddSeconds($periodRangeTime)
    $periodRange = (Get-Date).Addminutes($periodRangeTime)
    # $periodRange = (Get-Date).AddHours($periodRangeTime)
    # $periodRange = (Get-Date).AddDays($periodRangeTime)


    LogMessage -Message "<TRACE>fetch lastest $periodRangeTime minute data";


    $notFoundEvent = 'True'
    try { 
            '###############################get window###############################'
            $periodRange
            $winFailedAppMsg = Get-WinEvent -FilterHashTable @{LogName = "Application";ID = 1000, 1002 ; StartTime = $periodRange } -ErrorAction Stop
            

        }

    catch [Exception] {
            if ($_.Exception -match "No events were found that match the specified selection criteria") {
                Write-Host "No events found";
                $notFoundEvent = 'False'
            }
        }


    if ($notFoundEvent -eq 'False'){

      Write-Output "<TRACE> There is no windows application error event of this app"
      LogMessage -Message "<TRACE> There is no windows application error event of this app";
    } else {

        '<TRACE> There is a list found of the event error Event ID=1000, 1002'
        LogMessage -Message "<TRACE> There is a list found of the event error Event ID=1000, 1002";
        $exceptionWinList = @()


        $winFailedAppMsg

        foreach ($item in $winFailedAppMsg) 
        {

            $string = [String]$item.Message

## test case
# $string = "Faulting application name: BrnLotSrv.exe, version: 4.1.3.0, time stamp: 0x5f2cbe44
# Faulting module name: MSVCR100.dll, version: 10.0.40219.325, time stamp: 0x4df2be1e
# Exception code: 0x40000015
# Fault offset: 0x0008d6fd
# Faulting process id: 0x1d5c
# Faulting application start time: 0x01d8a253d5d9ae83
# Faulting application path: \\tbwburnapp03\C$\software\BurnLotServer\BrnLotSrv.exe
# Faulting module path: C:\WINDOWS\SYSTEM32\MSVCR100.dll
# Report Id: 69cad11f-eb62-4ab8-bd6d-a9ec25223d97
# Faulting package full name: 
# Faulting package-relative application ID: "

            $string = $string.ToUpper()
    
            try {

                ## search string from the windows event message.    

                $firstString = "APPLICATION PATH"
                $secondString= ".EXE"
                $pattern = "$firstString(.*?)$secondString"

                $thisException = [regex]::Match($string,$pattern).Value

                $thisException = $thisException.replace("APPLICATION PATH: ","")

                $exceptionWinList += $thisException


                }
            catch {
                    #$_.Exception
                }

        }


    # $exceptionWinList 


    LogMessage -Message "<TRACE> Start to compare the excption item with targeted application.";


        $csv | ForEach-Object {

            foreach ($thisException in $exceptionWinList) { 

                'exception~~~~'
                
                'current check'
                $currentCheck = [regex]::escape($_.AppPath).ToUpper()
                $currentCheck
                'this exception'
                $thisException = [regex]::escape($thisException)
                $thisException

                if ($thisException -eq $currentCheck) {

                    $excetipnFoundmsg = '<WARNING> Found a failed application! Exception text: ' + $thisException + ' matches ' + $_.AppPath
                    $excetipnFoundmsg
                    LogMessage -Message $excetipnFoundmsg;

                    $thisFailedApp = $_



                    $failedApps += $_.AppName.ToString();

                } else{

                    ## if exception name is a sub application under the main targeted applicaiton, put it into the failed app as well. 


                    if ($thisException -Match 'mtdispatchsrv.exe' -and $_ -eq '%DispatchMgr%') {
                    # $thisFailedApp = 'mtdispatchsrv.exe'


                    # if ($thisException -eq 'MTDispatchSrv.EXE' -and $currentCheck -eq '*DispatchMgr*' ){

                        $excetipnFoundmsg = '<WARNING> Found a failed application! Exception text: ' + $thisException + ' matches ' + $_
                        $excetipnFoundmsg
                        LogMessage -Message $excetipnFoundmsg;

                        $thisFailedApp = $_
                        # $thisFailedApp = $_ -replace "%",""
                        # $thisFailedApp = $thisFailedApp.replace("\","")

                        $failedApps += $thisFailedApp.ToString();

                    }




                }

             }

        }


    }
    LogMessage -Message "<TRACE>Exception Check - End";
    ####################################################                  
    # # Exception Detetion End  
    #################################################### 
}



$failedApps = $failedApps | Sort-Object -Property @{Expression={$_.Trim()}} -Unique



LogMessage -Message "Print the failed app section"
 foreach ($thisFailedApp in $failedApps) {

    
    if ($debugMode -eq 0){
        LogMessage -Message "<WARNING>    |FailedAppName|,     |$thisFailedApp|";
    }else{
        LogMessage -Message "<WARNING>    |TestFailedAppName|,     |$thisFailedApp|"; 
    }


 }


'All the failed apps:'
$failedApps;
'Fail apps Count: '
$failedApps.count;

#########################################
### Restart the services
#########################################
if ($turnOnRecovery -eq 1){
    LogMessage -Message '<RECOVERY SCRIPT START>';
    '<RECOVERY SCRIPT START>'
    if($failedApps.count -ne 0){

        'Trying to restart the sevices ... '

        foreach ($thisFailedApp in $failedApps) {
       

            try{

                $failedAppCSVIdx =  [array]::FindIndex(@($ProcessesToCheckFor),[Predicate[String]]{param($s)$s -eq $thisFailedApp})

                $failedAppCSVIdx

                try{


                    LogMessage -Message "<TRACE>AutoRecovery session for: $($thisFailedApp),  csvIdx: $($failedAppCSVIdx)";
                    "<TRACE>AutoRecovery session for: $($thisFailedApp),  csvIdx: $($failedAppCSVIdx)"


            
                    ## kill the app running on the background
                    LogMessage -Message "Start to Kill";
                    LogMessage -Message "<TRACE>Clear the $thisFailedApp running on the background";
                    try{
                        



                        LogMessage -Message "Now killing: $thisFailedApp";
                        Write-Host ("<TRACE>Now killing: {0}" -f $thisFailedApp)


                        $thisFailedAppPath = $csv[$failedAppCSVIdx].AppPath.ToString() 

                        $targetedAppEscapePath = [regex]::escape($thisFailedAppPath)

                        $failedObj = Get-WmiObject Win32_Process | where Path -match $targetedAppEscapePath 


                        if (![string]::IsNullOrEmpty($failedObj)) {

                            $failedObj | ForEach-Object {

                                LogMessage -Message "Terminating... $($_) .";
                                if ($debugMode -eq 0){
                                    $_.Terminate()
                                }

                            }

                        }else {
                            LogMessage -Message "Can't find the path: $($thisFailedAppPath)  running on the background.";
                            "Can't find the path: $($thisFailedAppPath)  running on the background."
                        }


                    }
                    catch {

                        $ErrorMessage = $_.Exception.Message
                        Write-Host ("Exception: {0}" -f $ErrorMessage)
                        LogMessage -Message "$ErrorMessage";

                        Write-Host ("There is no {0}, which is not running on the background that can be stopped" -f $thisFailedApp)
                        LogMessage -Message "There is no $thisFailedApp, which is not running on the background that can be stopped";


                    }
                    "End Kill, sleep for 3 seconds"
                    LogMessage -Message "End Kill, sleep for 3 seconds";

                    ## end Kill
                    Start-Sleep -s 3
                    
                    ## restart the failed apps

                    LogMessage -Message "Start to Restart the app $thisFailedApp";


                    $com = @($csv.CommandLine)[[int]$failedAppCSVIdx]
                    $wor = @($csv.Workdir)[[int]$failedAppCSVIdx]

                    $processArgs = @($com, $wor)

                    if ($debugMode -eq 0){
                        $result = Invoke-WmiMethod -Path win32_process -Name create -ArgumentList $processArgs
                    }


                    "End Restart, sleep for 15 seconds"
                    LogMessage -Message "End Restart, sleep for 5 seconds";
                    Start-Sleep -s 5


                    $getApp = Get-WmiObject Win32_Process -Filter "commandline like '$thisFailedApp'" | Select-Object ProcessId, Name, Path, CommandLine
                    if (![string]::IsNullOrEmpty($getApp.ProcessId)) {
                        $app_pid = $getApp.ProcessId
                        $app_name = $getApp.Name
                        Write-Host ("Restarted app: {0}, pid = {1} " -f $app_name, $app_pid)
                        LogMessage -Message "<TRACE>The restarted app: $($app_name), now current pid = $($app_pid)";  

                    }
                    else {

                        Write-Host ("Failed to get the pid of the restarted app" -f $thisFailedApp)
                        LogMessage -Message "<WARNING>Failed to get the pid of the restarted app: $thisFailedApp";  
                    }

         
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    Write-Debug ("Exception: {0}" -f $ErrorMessage)
                    Write-Host ("Failed to restart the process ... : {0}" -f $thisFailedApp)
                    LogMessage -Message "<WARNING>Failed to restart the process ... : $thisFailedApp";
                    LogMessage -Message $ErrorMessage;
                    $Global:ReturnStatus = "Fail"
                    $Global:ReturnMessage = "Failed to open the App ... : $thisFailedApp"
                    # return
                }

            }
            catch{
                    $ErrorMessage = $_.Exception.Message
                    Write-Debug ("Exception: {0}" -f $ErrorMessage)
                    Write-Debug ("Failed to find the matched failedApp list ... : {0}" -f $thisFailedApp)
                    LogMessage -Message "<WARNING>Failed to find the matched failedApp list ... : $thisFailedApp";
                    LogMessage -Message $ErrorMessage;
                    $Global:ReturnStatus = "Fail"
                    $Global:ReturnMessage = "Failed to find the matched failedApp list ... : $thisFailedApp"
                    # return
            }

        }
    }else {
        LogMessage -Message "<TRACE>There is no app to be restarted";
        '<TRACE>There is no app to be restarted'
    }

    LogMessage -Message '<RECOVERY SCRIPT END>';
}