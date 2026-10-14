# Execution history supplies candidates automatically; it does not establish maliciousness.
function Get-ExecutionHistory([int]$Hours=72){
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 foreach($user in Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue|Where-Object PSChildName -match '^S-1-5-21-[\d-]+$'){
  $userSid=$user.PSChildName;$profile=''
  try{$profile=(Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$userSid)).ProfileImagePath}catch{}
  $base='Registry::HKEY_USERS\'+$userSid+'\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
  if(!(Test-Path -LiteralPath $base)){continue}
  foreach($group in Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue){
   $location=$group.PSPath+'\Count';if(!(Test-Path -LiteralPath $location)){continue};$key=Get-Item -LiteralPath $location
   foreach($name in $key.GetValueNames()){
    $data=$key.GetValue($name);if($data -isnot [byte[]] -or $data.Length -lt 68){continue}
    try{$stamp=[datetime]::FromFileTimeUtc([BitConverter]::ToInt64($data,60));if($stamp -lt [datetime]::UtcNow.AddHours(-$Hours)){continue}}catch{continue}
    $decoded=-join ([char[]]$name|ForEach-Object {$c=[int]$_;if($c -ge 65 -and $c -le 90){[char](65+($c-65+13)%26)}elseif($c -ge 97 -and $c -le 122){[char](97+($c-97+13)%26)}else{$_}})
    $path=$decoded
    if($profile){$path=$path -replace '(?i)^\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641\}',($profile+'\Desktop') -replace '(?i)^\{374DE290-123F-4565-9164-39C4925E467B\}',($profile+'\Downloads')}
    if($path -notmatch '^[A-Za-z]:\\.+\.(exe|com|scr|msi|bat|cmd|ps1|vbs|js|hta)$'){continue}
    [pscustomobject]@{Source='UserAssist';Sid=$userSid;Path=$path;TimeUtc=$stamp.ToString('o');Location=$location;ValueName=$name;Meaning='Explorer记录的启动痕迹；不证明载荷成功执行或当前驻留'}
   }
  }
 }
}
function Get-CrashEvidence([int]$Hours=72){
 $limit=[datetime]::UtcNow.AddHours(-$Hours);$count=0
 foreach($root in @("$env:ProgramData\Microsoft\Windows\WER\ReportQueue","$env:ProgramData\Microsoft\Windows\WER\ReportArchive")){
  if(!(Test-Path -LiteralPath $root)){continue}
  foreach($dir in Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 60){
   if($dir.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
   $file=Join-Path $dir.FullName 'Report.wer';if(!(Test-LocalArtifact $file)){continue}
   try{
    $fi=Get-Item -LiteralPath $file;if($fi.Length -gt 1MB){continue};$kv=@{}
    foreach($line in Get-Content -LiteralPath $file){$at=$line.IndexOf('=');if($at -gt 0){$kv[$line.Substring(0,$at)]=$line.Substring($at+1)}}
    if($kv.EventType -notmatch 'APPCRASH|BEX'){continue}
    $time=[datetime]::FromFileTimeUtc([long]$kv.EventTime);if($time -lt $limit){continue}
    [pscustomobject]@{Source='Windows Error Reporting';ReportPath=$file;TimeUtc=$time.ToString('o');AppPath=$kv.AppPath;AppName=$kv['Sig[0].Value'];FaultModule=$kv['Sig[3].Value'];ExceptionCode=$kv['Sig[6].Value'];ExceptionOffset=$kv['Sig[7].Value'];ReportId=$kv.ReportIdentifier;LoadedModules=@($kv.Keys|Where-Object {$_ -like 'LoadedModule*'}|ForEach-Object {$kv[$_]})}
    $count++
   }catch{Gap ('崩溃报告 '+$file) $_.Exception.Message}
  }
 }
}
function Get-TransientExecutions($Raw,$Analysis){
 foreach($h in $Raw.ExecutionHistory){
  if($h.Path -eq $Raw.Host.CollectorPath){continue}
  $when=[datetime]$h.TimeUtc
  $deletes=@($Raw.Journals|ForEach-Object {$_.Changes}|Where-Object {$_.PathResolved -and $_.Path -eq $h.Path -and ([uint32]$_.Reason -band 0x200) -and ([datetime]$_.TimeUtc) -ge $when -and ([datetime]$_.TimeUtc) -le $when.AddSeconds(120)}|Sort-Object TimeUtc)
  if(!$deletes.Count){continue}
  $crashes=@($Raw.Crashes|Where-Object {([datetime]$_.TimeUtc) -ge $when -and ([datetime]$_.TimeUtc) -le $when.AddSeconds(30)})
  $meta=@($Analysis.Files|Where-Object Path -eq $h.Path|Select-Object -First 1)
  [pscustomobject]@{Path=$h.Path;Launch=$h;Deletion=$deletes[0];DeleteAfterSeconds=[math]::Round((([datetime]$deletes[0].TimeUtc)-$when).TotalSeconds,2);Crashes=$crashes;File=$meta;Severity=if($crashes.Count){'高'}else{'中'};Conclusion=if($crashes.Count){'程序启动后快速删除，同一时间窗口出现进程崩溃'}else{'程序启动后短时间内被删除'};Limit='时间关联不证明该程序导致崩溃；删除记录没有操作者信息，不能直接认定自删除或木马家族。'}
 }
}
