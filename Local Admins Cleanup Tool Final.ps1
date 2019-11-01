#Pulls all localadmins from remote server
#Drops them in a new Standard AD group in your Security Groups OU (GRP_ServerName_Admin)
#Adds new group to server's local admins
#removes individually added domain users
#Drops 'Domain Users' from anything that might have it

$servers = Import-Csv "\\Path\To\ServerList.csv"

foreach ($server in $servers) {
  #assemble group name for DC and create it

  $name = $server.server
  $grpName = -join ("GRP_","$name","_Admin")
  "Creating new group for admins $grpname..."
  New-ADGroup -Name "$grpname" -GroupScope Global -Path "OU=Security Groups,DC=uscold,DC=com"

  #assemble group name for RC & Add to Local Admins
  Invoke-Command -ComputerName $name -ScriptBlock {
  
  #check if LocalAccounts module exists, if not grab it from a share
  $modtest = Test-Path -Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.LocalAccounts"
    
    if ($modtest -eq $true){
        "$name has the module loaded, importing module..."
        import-module Microsoft.PowerShell.LocalAccounts
    }

    if ($modtest -eq $false){
        "LocalAccounts module not found, copying module from hqsvr... "
        cd C:\Windows\System32\WindowsPowerShell\v1.0\Modules
        mkdir Microsoft.PowerShell.LocalAccounts
        xcopy "\\Path\To\Share\Microsoft.PowerShell.LocalAccounts" "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.LocalAccounts"
        import-module Microsoft.PowerShell.LocalAccounts
    }
    
    $name = $env:COMPUTERNAME
    $grpname = -join ("GRP_","$name","_Admin")
    $grpname1 = -join ("USCOLD\","$grpname")
    
    #now the remote server nees to see the new AD group, quickest is via a retry
    #keep retrying group add until it becomes available (usually takes ~1-2min)
    $count = 0
    do {
      try {
        Add-LocalGroupMember -Group "Administrators" -Member $grpname -ErrorAction Stop
        $success = $true
      }
      catch {
        Write-Output "Don't see the new group in AD yet ... next attempt in 3 seconds"
        Start-Sleep -Seconds 3
      }

      $count++

    } until ($count -eq 1000 -or $success)
    if (-not ($success)) { exit }

    "Succes! Added goup:$grpname to server:$name"
    }

  #get local admins from remote server, running on DC
  "getting all local admins currently on server..."
  $users = Invoke-Command -ComputerName $name {


    (([adsi]"WinNT://./Administrators").psbase.Invoke('Members') |
      ForEach-Object {
        $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null)
      }) -match '^WinNT';
    }

  #filter 
  $users = $users -replace "WinNT://",""
  $fusers = $users | Where-Object { $_ -match "USCOLD" -and $_ -notmatch "Domain Admins" -and $_ -notmatch "Domain Users" -and $_ -notmatch "Administrator" -and $_ -notmatch "$grpname1" -and $_ -notmatch "$grpname" }

  ##domain users check & remove
  $dusers = Invoke-Command -ComputerName $name {

    (([adsi]"WinNT://./Administrators").psbase.Invoke('Members') |
      ForEach-Object {
        $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null)
      }) -match '^WinNT'; 
    $dusers = $dusers -replace "WinNT://","" 
    $dusers = $dusers | Where-object { $_ -match "Domain Users"}
    }

    if ($dusers -ne $null){
        
        Write-Output "Found Domain Users in Admins! Removing..."

        Invoke-Command -ComputerName $name {

    $dusers = 
    
      (([adsi]"WinNT://./Administrators").psbase.Invoke('Members') |
      ForEach-Object {
        $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null)
      }) -match '^WinNT'; 

    $dusers = $dusers -replace "WinNT://","" 
    $dusers = $dusers | Where-object { $_ -match "Domain Users"}
       
           foreach ($duser in $dusers){
           $dusersplit = $duser.Substring($duser.IndexOf('/') + 1)
           Remove-LocalGroupMember -Group "Administrators" -Member "$dusersplit" 
           }
        }    
    }

  ##
  foreach ($fuser in $fusers)
  {
    #drop uscold\ off string for samaccoutname
    $split = $fuser.Substring($fuser.IndexOf('/') + 1)
    #add each user from RC to new group
    Add-ADGroupMember -Identity "$grpname" -Members "$split"
    "Added user $split to $grpname"
  }

  #get local admins on server 
  Invoke-Command -ComputerName $name -ScriptBlock {
    $name = $env:COMPUTERNAME
    $grpname = -join ("GRP_","$name","_Admin")
    $grpname1 = -join ("USCOLD\","$grpname")
    $users = @(
      ([adsi]"WinNT://./Administrators").psbase.Invoke('Members') |
      ForEach-Object {
        $_.GetType().InvokeMember('AdsPath','GetProperty',$null,$($_),$null)
      }) -match '^WinNT';
    $users = $users -replace "WinNT://",""
    $fusers = $users | Where-Object { $_ -match "USCOLD" -and $_ -notmatch "Domain Admins" -and $_ -notmatch "Server Operators" -and $_ -notmatch "Administrator" -and $_ -notmatch "$grpname1" -and $_ -notmatch "$grpname" }

    foreach ($fuser in $fusers) {
      #remove users from server's local admin"
      "Removing $fuser from local administrators"
      $split = $fuser.Substring($fuser.IndexOf('/') + 1)
      Remove-LocalGroupMember -Group "Administrators" -Member "$split"
      Start-sleep -s 1

    }
  }
}
