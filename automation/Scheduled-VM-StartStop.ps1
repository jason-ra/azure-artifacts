    <#
        .DESCRIPTION
            Azure Automation Runbook - PowerShell Workflow.
            Scheduled-VM-StartStop.ps1
            
            Scheduled startup and shutdown of VMs. Reading tag values in CRONTAB format.
            Expected to be scheduled hourly. Ie. if scheduled to run at 13:20 - shutdown or start VMs
            where the tag value is hour = 13.

            Tag powerOffTime for 'Stop' action
            Tag powerOnTime for 'Start' action

            Example tag values
                * 20 * * 4     = 8PM on Thursdays
                * 18 * * 1-5   = 6PM Monday to Friday
                * 18-23 * * *  = Every hour between 6PM and 11PM
                See visualiser tool for help: https://crontab.guru/
        
            Author: Jason Raaschou https://github.com/jason-ra/
        
        .PARAMETER AzureSubscriptionId
            The target Azure Subscription to list VMs

        #.PARAMETER AzureVMList
        #    [Optional] Defaults to All. Otherwise can specify a comma separated list of VM names

        .PARAMETER Action
            Either 'Start' or 'Stop'

        .PARAMETER TimeZoneAdjust
            [Optional] Adjusts UTC to local time zone (default +10 AEST)

        .EXAMPLE Start all VMs in Subscription ID# 5fe6c3ef-32e2-4e37-8164-1314c0fb93d8 in AEST
            Scheduled-VM-StartStop -AzureSubscriptionId '5fe6c3ef-32e2-4e37-8164-1314c0fb93d8' -Action Start -TimeZoneAdjust 10

    #>
workflow Scheduled-VM-StartStop
{ 
    Param 
    (    
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] 
        [String] 
        $AzureSubscriptionId, 
        #[Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] 
        #[String] 
        #$AzureVMList="All", 
        [Parameter(Mandatory=$true)][ValidateSet("Start","Stop")] 
        [String] 
        $Action,
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]
        [Int]
        $TimeZoneAdjust=10
    ) 
    $ErrorActionPreference = "Continue"
    $ActionTime = (([DateTime]::UtcNow) + (New-TimeSpan -Hours $TimeZoneAdjust))

    $connectionName = "AzureRunAsConnection"
    try
    {
        # Get the connection "AzureRunAsConnection "
        $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

        "Logging in to Azure..."
        Add-AzureRmAccount `
            -ServicePrincipal `
            -TenantId $servicePrincipalConnection.TenantId `
            -ApplicationId $servicePrincipalConnection.ApplicationId `
            -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
    }
    catch {
        if (!$servicePrincipalConnection)
        {
            $ErrorMessage = "Connection $connectionName not found."
            throw $ErrorMessage
        } else{
            Write-Error -Message $_.Exception
            throw $_.Exception
        }
    }

    if($Action -eq 'Stop') {
        $tagName = 'powerOffTime'
    } else {
        $tagName = 'powerOnTime'
    }
    "Finding VMs..."
    $AzureVMs = @()
    $AllAzureVMs = Get-AzureRmVM
    foreach ($VM in $AllAzureVMs) {
        if ($VM.Tags[$tagName] -ne $null) {
            if (Test-CronExpression -Expression $VM.Tags[$tagName] -DateTime $ActionTime -VMName $VM.Name) {
                $AzureVMs += $VM.Name
            }
        }
    } 
    $AzureVMsToHandle = $AzureVMs
 
    if($AzureVMs.Count -lt 1) {
        Write-Output "No VMs match the pattern. Exiting"
    }
    else
    {
        foreach($AzureVM in $AzureVMsToHandle) 
        { 
            if(!(Get-AzureRmVM | ? {$_.Name -eq $AzureVM})) 
            { 
                throw " AzureVM : [$AzureVM] - Does not exist! - Check your inputs " 
            } 
        } 
    
        if($Action -eq "Stop") 
        { 
            #Write-Output "Stopping VMs"; 
            foreach -parallel ($AzureVM in $AzureVMsToHandle) 
            { 
                Write-Output "Stopping $($AzureVM)"
                Get-AzureRmVM | ? {$_.Name -eq $AzureVM} | Stop-AzureRmVM -Force 
            } 
        } 
        else 
        { 
            #Write-Output "Starting VMs"; 
            foreach -parallel ($AzureVM in $AzureVMsToHandle) 
            { 
                Write-Output "Starting $($AzureVM)"
                Get-AzureRmVM | ? {$_.Name -eq $AzureVM} | Start-AzureRmVM 
            } 
        } 
    }
    function Test-CronExpression {
    <#
        .DESCRIPTION
            PowerShell cron expression parser, to check if a date/time matches a cron expression
            Format:
                <min> <hour> <day-of-month> <month> <day-of-week>
            Source:
                https://gist.github.com/Badgerati/19f2721bc5bf9222417d36362b04d9e2
        
        .PARAMETER Expression
            A cron expression to validate

        .PARAMETER DateTime
            [Optional] A specific date/time to check cron expression against. (Default: DateTime.Now)

        .EXAMPLE Test expression against the current date/time
            Test-CronExpression -Expression '5/7 * 29 FEB,MAR *'

        .EXAMPLE Test expression against a specific date/time
            Test-CronExpression -Expression '5/7 * 29 FEB,MAR *' -DateTime ([DateTime]::Now)
    #>

        param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [string]
            $Expression,
            [Parameter()]
            $DateTime = $null,
            [Parameter()]
            [string]
            $VMName
        )

        function Get-CronFields
        {
            return @(
                'Minute',
                'Hour',
                'DayOfMonth',
                'Month',
                'DayOfWeek'
            )
        }

        function Get-CronFieldConstraints
        {
            return @{
                'MinMax' = @(
                    @(0, 59),
                    @(0, 23),
                    @(1, 31),
                    @(1, 12),
                    @(0, 6)
                );
                'DaysInMonths' = @(
                    31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
                );
                'Months' = @(
                    'January', 'February', 'March', 'April', 'May', 'June', 'July',
                    'August', 'September', 'October', 'November', 'December'
                )
            }
        }

        function Get-CronPredefined
        {
            return @{
                # normal
                '@minutely' = '* * * * *';
                '@hourly' = '0 * * * *';
                '@daily' = '0 0 * * *';
                '@weekly' = '0 0 * * 0';
                '@monthly' = '0 0 1 * *';
                '@quarterly' = '0 0 1 1,4,7,10';
                '@yearly' = '0 0 1 1 *';
                '@annually' = '0 0 1 1 *';

                # twice
                '@semihourly' = '0,30 * * * *';
                '@semidaily' = '0 0,12 * * *';
                '@semiweekly' = '0 0 * * 0,4';
                '@semimonthly' = '0 0 1,15 * *';
                '@semiyearly' = '0 0 1 1,6 *';
                '@semiannually' = '0 0 1 1,6 *';
            }
        }

        function Get-CronFieldAliases
        {
            return @{
                'Month' = @{
                    'Jan' = 1;
                    'Feb' = 2;
                    'Mar' = 3;
                    'Apr' = 4;
                    'May' = 5;
                    'Jun' = 6;
                    'Jul' = 7;
                    'Aug' = 8;
                    'Sep' = 9;
                    'Oct' = 10;
                    'Nov' = 11;
                    'Dec' = 12;
                };
                'DayOfWeek' = @{
                    'Sun' = 0;
                    'Mon' = 1;
                    'Tue' = 2;
                    'Wed' = 3;
                    'Thu' = 4;
                    'Fri' = 5;
                    'Sat' = 6;
                };
            }
        }

        function ConvertFrom-CronExpression
        {
            param (
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [string]
                $Expression,
                [Parameter()]
                [string]
                $VMName
            )

            $Expression = $Expression.Trim()

            # check predefineds
            $predef = Get-CronPredefined
            if ($null -ne $predef[$Expression]) {
                $Expression = $predef[$Expression]
            }

            # split and check atoms length
            $atoms = @($Expression -isplit '\s+')
            if ($atoms.Length -ne 5) {
                Write-Error "Cron expression should only consist of 5 parts: $($Expression) [$($VMName)]"
                return $false
            }

            # basic variables
            $aliasRgx = '(?<tag>[a-z]{3})'

            # get cron obj and validate atoms
            $fields = Get-CronFields
            $constraints = Get-CronFieldConstraints
            $aliases = Get-CronFieldAliases
            $cron = @{}

            for ($i = 0; $i -lt $atoms.Length; $i++)
            {
                $_cronExp = @{
                    'Range' = $null;
                    'Values' = $null;
                }

                $_atom = $atoms[$i]
                $_field = $fields[$i]
                $_constraint = $constraints.MinMax[$i]
                $_aliases = $aliases[$_field]

                # replace day of week and months with numbers
                switch ($_field)
                {
                    { $_field -ieq 'month' -or $_field -ieq 'dayofweek' }
                        {
                            while ($_atom -imatch $aliasRgx) {
                                $_alias = $_aliases[$Matches['tag']]
                                if ($null -eq $_alias) {
                                    Write-Error "Invalid $($_field) alias found: $($Matches['tag']) [$($VMName)]"
                                }

                                $_atom = $_atom -ireplace $Matches['tag'], $_alias
                                $_atom -imatch $aliasRgx | Out-Null
                            }
                        }
                }

                # ensure atom is a valid value
                if (!($_atom -imatch '^[\d|/|*|\-|,]+$')) {
                    Write-Error "Invalid atom character: $($_atom) [$($VMName)]"
                }

                # replace * with min/max constraint
                $_atom = $_atom -ireplace '\*', ($_constraint -join '-')

                # parse the atom for either a literal, range, array, or interval
                # literal
                if ($_atom -imatch '^\d+$') {
                    $_cronExp.Values = @([int]$_atom)
                }

                # range
                elseif ($_atom -imatch '^(?<min>\d+)\-(?<max>\d+)$') {
                    $_cronExp.Range = @{ 'Min' = [int]($Matches['min'].Trim()); 'Max' = [int]($Matches['max'].Trim()); }
                }

                # array
                elseif ($_atom -imatch '^[\d,]+$') {
                    $_cronExp.Values = [int[]](@($_atom -split ',').Trim())
                }

                # interval
                elseif ($_atom -imatch '(?<start>(\d+|\*))\/(?<interval>\d+)$') {
                    $start = $Matches['start']
                    $interval = [int]$Matches['interval']

                    if ($interval -ieq 0) {
                        $interval = 1
                    }

                    if ([string]::IsNullOrWhiteSpace($start) -or $start -ieq '*') {
                        $start = 0
                    }

                    $start = [int]$start
                    $_cronExp.Values = @($start)

                    $next = $start + $interval
                    while ($next -le $_constraint[1]) {
                        $_cronExp.Values += $next
                        $next += $interval
                    }
                }

                # error
                else {
                    Write-Error "Invalid cron atom format found: $($_atom) [$($VMName)]"
                }

                # ensure cron expression values are valid
                if ($null -ne $_cronExp.Range) {
                    if ($_cronExp.Range.Min -gt $_cronExp.Range.Max) {
                        Write-Error "Min value for $($_field) should not be greater than the max value [$($VMName)]"
                    }

                    if ($_cronExp.Range.Min -lt $_constraint[0]) {
                        Write-Error "Min value '$($_cronExp.Range.Min)' for $($_field) is invalid, should be greater than/equal to $($_constraint[0]) [$($VMName)]"
                    }

                    if ($_cronExp.Range.Max -gt $_constraint[1]) {
                        Write-Error "Max value '$($_cronExp.Range.Max)' for $($_field) is invalid, should be less than/equal to $($_constraint[1]) [$($VMName)]"
                    }
                }

                if ($null -ne $_cronExp.Values) {
                    $_cronExp.Values | ForEach-Object {
                        if ($_ -lt $_constraint[0] -or $_ -gt $_constraint[1]) {
                            Write-Error "Value '$($_)' for $($_field) is invalid, should be between $($_constraint[0]) and $($_constraint[1]) [$($VMName)]"
                        }
                    }
                }

                # assign value
                $cron[$_field] = $_cronExp
            }

            # post validation for month/days in month
            if ($null -ne $cron['Month'].Values -and $null -ne $cron['DayOfMonth'].Values)
            {
                foreach ($mon in $cron['Month'].Values) {
                    foreach ($day in $cron['DayOfMonth'].Values) {
                        if ($day -gt $constraints.DaysInMonths[$mon - 1]) {
                            Write-Error "$($constraints.Months[$mon - 1]) only has $($constraints.DaysInMonths[$mon - 1]) days, but $($day) was supplied [$($VMName)]"
                        }
                    }
                }

            }

            # return the parsed cron expression
            return $cron
        }

        function Test-RangeAndValue($AtomContraint, $NowValue) {
            if ($null -ne $AtomContraint.Range) {
                if ($NowValue -lt $AtomContraint.Range.Min -or $NowValue -gt $AtomContraint.Range.Max) {
                    return $false
                }
            }
            elseif ($AtomContraint.Values -inotcontains $NowValue) {
                return $false
            }

            return $true
        }

        # current time
        if ($null -eq $DateTime) {
            $DateTime = [datetime]::Now
        }

        # convert the expression
        $Atoms = ConvertFrom-CronExpression -Expression $Expression -VMName $VMName

        # check day of month
        if (!(Test-RangeAndValue -AtomContraint $Atoms.DayOfMonth -NowValue $DateTime.Day)) {
            return $false
        }

        # check day of week
        if (!(Test-RangeAndValue -AtomContraint $Atoms.DayOfWeek -NowValue ([int]$DateTime.DayOfWeek))) {
            return $false
        }

        # check month
        if (!(Test-RangeAndValue -AtomContraint $Atoms.Month -NowValue $DateTime.Month)) {
            return $false
        }

        # check hour
        if (!(Test-RangeAndValue -AtomContraint $Atoms.Hour -NowValue $DateTime.Hour)) {
            return $false
        }

        # check minute
        if (!(Test-RangeAndValue -AtomContraint $Atoms.Minute -NowValue $DateTime.Minute)) {
            return $false
        }

        # date is valid
        return $true
    }

}
