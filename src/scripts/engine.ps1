param([Parameter(Mandatory=$true)][string]$Output, [string]$InputEvidence, [int]$Hours=72, [int]$MaxEvents=1500, [int]$MaxFiles=3000, [string]$IocFile)
$ErrorActionPreference='Stop'
$InformationPreference='Continue'
$env:PSModulePath="$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules;$env:ProgramFiles\WindowsPowerShell\Modules;$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
Import-Module "$PSHOME\Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1" -ErrorAction Stop
$started=Get-Date
$utf8=New-Object System.Text.UTF8Encoding($true)
$null=New-Item -ItemType Directory -Path $Output -Force
$Output=[IO.Path]::GetFullPath($Output)
$coverage=New-Object 'System.Collections.Generic.List[object]'
$findings=New-Object 'System.Collections.Generic.List[object]'
$edges=New-Object 'System.Collections.Generic.List[object]'
$cache=@{}; $hashCount=0; $signatureCount=0; $optionalHashCount=0; $optionalSignatureCount=0; $criticalTargets=@{}; $physicalMetaCache=@{}
. (Get-IRScript 'packages.ps1')
. (Get-IRScript 'memory.ps1')
. (Get-IRScript 'history.ps1')
. (Get-IRScript 'journal.ps1')
. (Get-IRScript 'general.ps1')
. (Get-IRScript 'investigate.ps1')
. (Get-IRScript 'runtime.ps1')
. (Get-IRScript 'network.ps1')
function HashFile([string]$path) {
 $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 $sha=[Security.Cryptography.SHA256]::Create()
 try {return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')} finally {$sha.Dispose();$stream.Dispose()}
}
function Save($name,$value) { [IO.File]::WriteAllText((Join-Path $Output $name), (ConvertTo-Json -InputObject $value -Depth 14), $utf8) }
function Stage($name,[scriptblock]$block) {
 Write-Information ("采集：$name")
 [IO.File]::AppendAllText((Join-Path $Output 'progress.log'),((Get-Date).ToString('o')+' 开始 '+$name+[Environment]::NewLine),$utf8)
 $sw=[Diagnostics.Stopwatch]::StartNew()
 $data=New-Object 'Collections.Generic.List[object]'
 try { & $block | ForEach-Object {$data.Add($_)}; $coverage.Add([pscustomobject]@{Module=$name;Status='成功';Count=$data.Count;Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2);Detail=''}); return $data.ToArray() }
 catch { $coverage.Add([pscustomobject]@{Module=$name;Status='不可用/不完整';Count=$data.Count;Seconds=[math]::Round($sw.Elapsed.TotalSeconds,2);Detail=($_.Exception.Message+'; '+$_.ScriptStackTrace)}); return $data.ToArray() }
}
function Gap($name,$detail) { $coverage.Add([pscustomobject]@{Module=$name;Status='范围限制';Count=0;Seconds=0;Detail=$detail}) }
function PathOf([string]$command) {
 if(!$command){return ''}; $s=if($InputEvidence){$command.Trim()}else{[Environment]::ExpandEnvironmentVariables($command.Trim())}
 $s=$s -replace '^\\\?\?\\','' -replace '^\\SystemRoot', $env:SystemRoot
 if($s -match '^"([^"]+)"'){return $matches[1]}
 if($s -match '^(.+?\.(exe|dll|sys|ps1|vbs|js|bat|cmd))(?=\s|,|$)'){return $matches[1].Trim()}
 if(!$InputEvidence){try{if(Test-Path -LiteralPath $s -PathType Leaf -ErrorAction Stop){return $s}}catch{}}
 return ''
}
function WritableHint([string]$s) { return ($s -match '(?i)\\(Users|ProgramData|Temp|Downloads|AppData|Public)\\') }
function Meta([string]$path) {
 if(!$path){return $null}; if(!$InputEvidence){$path=[Environment]::ExpandEnvironmentVariables($path)}
 $critical=$criticalTargets.ContainsKey($path)
 if($cache.ContainsKey($path) -and !($critical -and $cache[$path].Signature -eq '未检查')){return $cache[$path]}
 if($InputEvidence){$m=[pscustomobject]@{Path=$path;Exists=$null;Size=$null;CreatedUtc='';ModifiedUtc='';SHA256='';Signature='证据未提供';Signer='';Error='离线材料未提供文件元数据；未读取分析电脑上的同名路径'};$cache[$path]=$m;return $m}
 $m=[ordered]@{Path=$path;Exists=$false;Size=0;CreatedUtc='';ModifiedUtc='';SHA256='';Signature='未检查';Signer='';Error=''}
 try {
  $fi=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if($fi.PSIsContainer){return $null}
  Initialize-IRFileProbe;$physical=[YingJiFile.Probe]::Canonical($path)
  if($physicalMetaCache.ContainsKey($physical)){
   $prior=$physicalMetaCache[$physical]
   if($prior.Size -eq $fi.Length -and $prior.ModifiedUtc -eq $fi.LastWriteTimeUtc.ToString('o') -and !($critical -and $prior.Signature -eq '未检查')){$copy=$prior.PSObject.Copy();$copy.Path=$path;$cache[$path]=$copy;return $copy}
  }
  $m.Attributes=[string]$fi.Attributes;$m.HiddenParent=IR-HiddenParent $path;$m.OriginalFilename=$fi.VersionInfo.OriginalFilename;$m.CompanyName=$fi.VersionInfo.CompanyName
  $m.ZoneIdentifier='';try{$zone=Get-Item -LiteralPath $path -Stream Zone.Identifier -ErrorAction Stop;if($zone.Length -le 16KB){$m.ZoneIdentifier=[string]::Copy([string](Get-Content -LiteralPath $path -Stream Zone.Identifier -Raw -ErrorAction Stop))}}catch{}
  $m.Exists=$true; $m.Size=$fi.Length; $m.CreatedUtc=$fi.CreationTimeUtc.ToString('o'); $m.ModifiedUtc=$fi.LastWriteTimeUtc.ToString('o')
  if($fi.Length -le 512MB -and ($critical -or $script:optionalHashCount -lt 1600)){try{$m.SHA256=HashFile $path;$script:hashCount++;if(!$critical){$script:optionalHashCount++}}catch{$m.Error='哈希失败：'+$_.Exception.Message}}else{$m.Error='哈希跳过：512MB/可选1600文件预算'}
  if($fi.Extension -match '^(?i)\.(exe|dll|sys|ps1|msi|ocx|cpl|drv|pyd|scr|com)$' -and ($critical -or $script:optionalSignatureCount -lt 2000)) { $script:signatureCount++;if(!$critical){$script:optionalSignatureCount++};$sig=Get-AuthenticodeSignature -LiteralPath $path; $m.Signature=[string]$sig.Status; if($sig.SignerCertificate){$m.Signer=$sig.SignerCertificate.Subject} }
 } catch {$m.Error=$_.Exception.Message}
 $o=[pscustomobject]$m; $cache[$path]=$o;if($physical){$physicalMetaCache[$physical]=$o};return $o
}
function Verify-IRCriticalTargets($raw) {
 $paths=@((IR-References $raw).Path)+@($raw.Processes.Path)+@($raw.Modules.Path)+@($raw.Crashes.LoadedModules)
 $paths=@($paths|Where-Object {$_}|Select-Object -Unique)
 foreach($p in $paths){$script:criticalTargets[$p]=$true}
 $timer=[Diagnostics.Stopwatch]::StartNew();$checked=0
 foreach($p in $paths){if($timer.Elapsed.TotalSeconds -ge 180){break};$null=Meta $p;$checked++}
 Gap '关键对象验证' ('启动配置、当前映像、全部实际加载模块及崩溃模块不受普通文件数量预算挤占；目标='+$paths.Count+'，完成='+$checked+'，耗时秒='+[math]::Round($timer.Elapsed.TotalSeconds,2)+'；180秒上限，剩余对象仍为未知。')
}
function Finding($severity,$title,$source,$target,$detail,$action) {
 $id='F{0:d4}' -f ($findings.Count+1)
 $findings.Add([pscustomobject]@{Id=$id;Severity=$severity;Title=$title;Source=$source;Target=$target;Evidence=$detail;Advice=$action;Verdict='线索，需核实恶意性'})
}
function Edge($from,$to,$kind,$proof,$confidence) { $edges.Add([pscustomobject]@{From=$from;To=$to;Relation=$kind;Evidence=$proof;Confidence=$confidence}) }
function EventRows($log,$ids) {
 try { $items=@(Get-WinEvent -FilterHashtable @{LogName=$log;Id=$ids;StartTime=(Get-Date).AddHours(-$Hours)} -MaxEvents $MaxEvents -ErrorAction Stop) }
 catch { if($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound'){Gap $log '查询范围内未返回匹配事件；不能证明历史行为不存在或审核配置完整。';return @()}; throw }
 if($items.Count -ge $MaxEvents){Gap $log "达到 $MaxEvents 条上限，只含最新记录；历史链可能缺失"}
 foreach($e in $items){
  $xml=[xml]$e.ToXml(); $d=@{}
  foreach($n in $xml.Event.EventData.Data){if($n.Name){$d[[string]$n.Name]=[string]$n.'#text'}}
  [pscustomobject]@{Log=$log;Id=$e.Id;RecordId=$e.RecordId;TimeUtc=$e.TimeCreated.ToUniversalTime().ToString('o');Data=$d;EmitterPid=[string]$xml.Event.System.Execution.ProcessID;Xml=$e.ToXml()}
 }
}
function RegValues($key,$names,$kind) {
 try {if(!(Test-Path -LiteralPath $key)){return};$item=Get-Item -LiteralPath $key;$valueNames=$item.GetValueNames()} catch {Gap ('注册表 '+$key) $_.Exception.Message;return}
 foreach($name in $valueNames) {
  if($names -and $name -notin $names){continue}
  $v=$item.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if($null -eq $v -or [string]$v -eq ''){continue}
  [pscustomobject]@{Kind=$kind;Location=$key;Name=$name;Command=($v -join ' ');Path=(PathOf ($v -join ' '));Enabled=$true;Principal='依键所属用户/系统';Extra=''}
 }
}
if($InputEvidence){
 Write-Output '离线证据回放（不采集本机）'
 $raw=Get-Content -LiteralPath $InputEvidence -Raw -Encoding UTF8 | ConvertFrom-Json
 foreach($c in $raw.Coverage){$coverage.Add($c)}
}else{
 $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 $hostinfo=[pscustomobject]@{Computer=$env:COMPUTERNAME;User=[Security.Principal.WindowsIdentity]::GetCurrent().Name;Admin=$admin;OS=[Environment]::OSVersion.VersionString;TimeUtc=$started.ToUniversalTime().ToString('o');TimeZone=[TimeZoneInfo]::Local.Id;SystemRoot=$env:SystemRoot;Version='1.13';Mode='现场只读取证';CollectorPath=$IRLauncher}
 if(!$admin){Gap '权限' '非管理员：其他用户进程、Security日志、部分模块/注册表/服务可能不可读。建议管理员重跑。'}
 Initialize-MemoryReader
 $debugPrivilege=[YingJiMemory.Reader]::EnableDebugPrivilege()
 if(!$debugPrivilege){Gap '调试权限' '本采集进程未获得SeDebugPrivilege，系统进程/模块可能不可读；不表示正常'}
 $processes=Stage '进程' {Get-CimInstance Win32_Process | ForEach-Object {[pscustomobject]@{Pid=$_.ProcessId;ParentPid=$_.ParentProcessId;Name=$_.Name;Path=$_.ExecutablePath;Command=$_.CommandLine;StartUtc=if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{''}}}}
 $networkCapture=@(Stage '实时网络与进程身份观察' {Get-IRNetworkObservation -directory $Output -seconds 30})
 $networkObservation=if($networkCapture.Count){$networkCapture[0]}else{$null}
 $processes=Stage '观察后进程身份' {Get-CimInstance Win32_Process | ForEach-Object {[pscustomobject]@{Pid=$_.ProcessId;ParentPid=$_.ParentProcessId;Name=$_.Name;Path=$_.ExecutablePath;Command=$_.CommandLine;StartUtc=if($_.CreationDate){$_.CreationDate.ToUniversalTime().ToString('o')}else{''}}}}
 $networkPids=@($networkObservation.Connections.Pid)+@($networkObservation.DNSEvents|ForEach-Object {$i=Resolve-IRDNSIdentity $_ $networkObservation;if($i.IdentityMatched){[int]$i.Pid}})
 $tcp=Stage 'TCP连接' {Get-NetTCPConnection | Select-Object @{n='Pid';e={$_.OwningProcess}},LocalAddress,LocalPort,RemoteAddress,RemotePort,@{n='State';e={[string]$_.State}}}
 $udp=Stage 'UDP端点' {Get-NetUDPEndpoint | Select-Object @{n='Pid';e={$_.OwningProcess}},LocalAddress,LocalPort}
 $dns=Stage 'DNS缓存' {Get-DnsClientCache | Select-Object Entry,Data,Type,TimeToLive}
 $services=Stage '服务' {Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,StartName,State,ProcessId}
 $drivers=Stage '驱动' {Get-CimInstance Win32_SystemDriver | Select-Object Name,PathName,StartMode,State,ServiceType}
 $reg=Stage '注册表持久化' {
  $bases=@('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node')
  foreach($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()){if($sid -match '^S-1-5-21-[\d-]+$'){$bases+=('Registry::HKEY_USERS\'+$sid+'\Software');$bases+=('Registry::HKEY_USERS\'+$sid+'\Software\WOW6432Node')}}
  foreach($b in $bases){
   foreach($k in @('Microsoft\Windows\CurrentVersion\Run','Microsoft\Windows\CurrentVersion\RunOnce','Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')){RegValues "$b\$k" @() 'Run/RunOnce'}
   RegValues "$b\Microsoft\Windows NT\CurrentVersion\Winlogon" @('Shell','Userinit','Taskman') 'Winlogon'
   RegValues "$b\Microsoft\Windows NT\CurrentVersion\Windows" @('AppInit_DLLs','Load','Run') 'AppInit/Load'
   foreach($k in @('Image File Execution Options','SilentProcessExit')) {
    $root="$b\Microsoft\Windows NT\CurrentVersion\$k"
    try {if(Test-Path -LiteralPath $root){$regErrors=@();$children=@(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue -ErrorVariable regErrors);foreach($err in $regErrors){Gap ('注册表子键 '+$root) $err.Exception.Message};foreach($child in $children){RegValues $child.PSPath @('Debugger','MonitorProcess') $k}}}catch{Gap ('注册表子键 '+$root) $_.Exception.Message}
   }
  }
  RegValues 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager' @('BootExecute') 'BootExecute'
  foreach($s in $services){RegValues "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters" @('ServiceDll') 'ServiceDll'}
 }
 $tasks=Stage '计划任务' {$taskBudget=0;foreach($t in Get-ScheduledTask){$storage=Get-IRTaskStorage $t;foreach($a in $t.Actions){$ti=$null;$err='';if((WritableHint $a.Execute) -and $taskBudget -lt 80){$taskBudget++;try{$ti=$t|Get-ScheduledTaskInfo}catch{$err=$_.Exception.Message}};[pscustomobject]@{Kind='Task';Location=$t.TaskPath+$t.TaskName;Name=$t.TaskName;TaskFile=$storage.TaskFile;RegistryTree=$storage.Tree;RegistryTask=$storage.IdKey;TaskGuid=$storage.Guid;Command=($a.Execute+' '+$a.Arguments).Trim();Path=(PathOf $a.Execute);Enabled=([string]$t.State -ne 'Disabled');Principal=$t.Principal.UserId;State=[string]$t.State;RunLevel=[string]$t.Principal.RunLevel;Triggers=(@($t.Triggers|ForEach-Object {$_.CimClass.CimClassName}) -join ',');LastRunUtc=if($ti -and $ti.LastRunTime){$ti.LastRunTime.ToUniversalTime().ToString('o')}else{''};LastResult=if($ti){[string]$ti.LastTaskResult}else{''};Extra=('WorkingDirectory='+$a.WorkingDirectory+';RunLevel='+$t.Principal.RunLevel+';InfoError='+$err)}}}}
 $startup=Stage '启动目录' {
  $dirs=@("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
  foreach($p in Get-CimInstance Win32_UserProfile){if($p.LocalPath){$dirs+=($p.LocalPath+'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')}}
  $ws=New-Object -ComObject WScript.Shell
  foreach($d in $dirs){if(Test-Path -LiteralPath $d){foreach($f in Get-ChildItem -LiteralPath $d -File -Force){
   $cmd=$f.FullName; $target=$cmd
   if($f.Extension -eq '.lnk'){$ln=$ws.CreateShortcut($f.FullName);$target=$ln.TargetPath;$cmd=$target+' '+$ln.Arguments}
   [pscustomobject]@{Kind='Startup';Location=$f.FullName;Name=$f.Name;Command=$cmd;Path=$target;Enabled=$true;Principal='目录所属用户';Extra=''}
  }}}
 }
 $wmi=Stage 'WMI永久订阅' {
  foreach($cl in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')){
   foreach($o in Get-CimInstance -Namespace root/subscription -ClassName $cl){[pscustomobject]@{Class=$cl;Name=$o.Name;Path=[string]$o.CimSystemProperties.Path;Command=$o.CommandLineTemplate;Script=$o.ScriptText;Query=$o.Query;Filter=[string]$o.Filter;Consumer=[string]$o.Consumer}}
  }
 }
 $users=Stage '本地账号' {Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name,SID,Disabled,Lockout,Status}
 $admins=Stage '本地管理员成员' {$g=Get-LocalGroup -SID 'S-1-5-32-544'; Get-LocalGroupMember -Group $g.Name | Select-Object Name,SID,PrincipalSource,ObjectClass}
 $defender=Stage 'Defender状态' {Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected}
 $exclusions=Stage 'Defender排除项' {Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,DisableRealtimeMonitoring}
 $detections=Stage 'Defender历史告警' {Get-MpThreatDetection | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,Resources,ActionSuccess,CurrentThreatExecutionStatusID}
 $events=@()
 $events+=Stage 'Sysmon日志' {EventRows 'Microsoft-Windows-Sysmon/Operational' @(1,7,8,10,11,12,13,14,19,20,21,25)}
 $events+=Stage 'Sysmon网络日志' {EventRows 'Microsoft-Windows-Sysmon/Operational' @(3,22)}
 $events+=Stage 'Security日志' {EventRows 'Security' @(4624,4625,4672,4688,4697,4698,4702,4720,4722,4732,1102)}
 $events+=Stage '网络允许日志' {EventRows 'Security' @(5156)}
 $events+=Stage '网络阻止日志' {EventRows 'Security' @(5157,5152,5153)}
 $events+=Stage 'DNS查询历史' {EventRows 'Microsoft-Windows-DNS-Client/Operational' @(3006,3008,3010,3011,3018,3019)}
 $events+=Stage 'System日志' {EventRows 'System' @(7045,7040,104)}
 $events+=Stage 'PowerShell日志' {EventRows 'Microsoft-Windows-PowerShell/Operational' @(4104)}
 $events+=Stage 'Defender事件' {EventRows 'Microsoft-Windows-Windows Defender/Operational' @(1116,1117,5001,5007)}
 $modules=Stage '加载模块' {Get-IRLoadedModules $processes}
 $memory=Stage '进程内存' {Get-MemoryEvidence $processes $networkPids}
 $imageIntegrity=Stage '主映像可执行节比较' {Get-IRImageIntegrity $processes $modules}
 $history=Stage '启动历史' {Get-ExecutionHistory -Hours $Hours}
 $journals=Stage 'NTFS文件变更' {Get-JournalEvidence $history}
 $crashes=Stage '程序崩溃历史' {Get-CrashEvidence -Hours $Hours}
 $recent=Stage '近期落地候选' {
  $roots=@("$env:USERPROFILE\Downloads","$env:TEMP","$env:APPDATA","$env:LOCALAPPDATA","$env:ProgramData") | Select-Object -Unique
  $queue=New-Object 'System.Collections.Generic.Queue[object]';foreach($r in $roots){$queue.Enqueue(@($r,0))};$seen=@{};$count=0;$dirsSeen=0;$clock=[Diagnostics.Stopwatch]::StartNew()
  while($queue.Count -and $count -lt $MaxFiles -and $dirsSeen -lt 1500 -and $clock.Elapsed.TotalSeconds -lt 15){
   $q=$queue.Dequeue();$d=[string]$q[0];$depth=[int]$q[1];if($seen.ContainsKey($d)){continue};$seen[$d]=$true;$dirsSeen++
   try {$children=@(Get-ChildItem -LiteralPath $d -Force -ErrorAction Stop)}catch{Gap ('目录 '+$d) $_.Exception.Message;continue}
   foreach($f in $children){
    if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
    if($f.PSIsContainer){if($depth -lt 2){$queue.Enqueue(@($f.FullName,$depth+1))};continue}
    if($f.Extension -match '^\.(exe|dll|sys|ps1|vbs|js|hta|bat|cmd|lnk|scr)$' -and $f.LastWriteTime -gt (Get-Date).AddHours(-$Hours)){
     [pscustomobject]@{Path=$f.FullName;Size=$f.Length;CreatedUtc=$f.CreationTimeUtc.ToString('o');ModifiedUtc=$f.LastWriteTimeUtc.ToString('o')};$count++;if($count -ge $MaxFiles){break}
    }
   }
  }
  Gap '文件搜索预算' "当前用户 Downloads/Temp/AppData 和 ProgramData，深度2、15秒、1500目录、$MaxFiles 文件；非全盘。实际访问 $dirsSeen 目录。"
 }
 $persist=@($reg)+@($tasks)+@($startup)
 foreach($s in $services){$persist+=[pscustomobject]@{Kind='Service';Location=('HKLM\SYSTEM\CurrentControlSet\Services\'+$s.Name);Name=$s.Name;Command=$s.PathName;Path=(PathOf $s.PathName);Enabled=($s.StartMode -ne 'Disabled');Principal=$s.StartName;State=$s.State;Pid=$s.ProcessId;StartMode=$s.StartMode;Extra=('StartMode='+$s.StartMode+';State='+$s.State+';PID='+$s.ProcessId)}}
 foreach($d in $drivers){$persist+=[pscustomobject]@{Kind='Driver';Location=('HKLM\SYSTEM\CurrentControlSet\Services\'+$d.Name);Name=$d.Name;Command=$d.PathName;Path=(PathOf $d.PathName);Enabled=($d.StartMode -ne 'Disabled');Principal='内核态';Extra=('State='+$d.State+';StartMode='+$d.StartMode)}}
 $extra=Stage '扩展驻留注册表与COM' {Get-IRExtraPersistence}
 foreach($s in $extra){
  $old=@($persist|Where-Object {$_.Kind -eq $s.Kind -and $_.Name -eq $s.Name -and ($s.Kind -in @('Service','Driver') -or $_.Location -eq $s.Location)})
  if($old.Count){foreach($o in $old){foreach($key in @('Path','Extra','Enabled','Principal','StartMode','ServiceName','RegistryStart','RegistryType')){if($null -ne $s.$key){$o|Add-Member -NotePropertyName $key -NotePropertyValue $s.$key -Force}}}}else{$persist+=@($s)}
 }
 foreach($w in $wmi|Where-Object {$_.Class -match 'EventConsumer'}){
  $bindings=@($wmi|Where-Object {$_.Class -eq '__FilterToConsumerBinding' -and $_.Consumer -like ('*'+$w.Name+'*')})
  $persist+=[pscustomobject]@{Kind='WMI';Location=$w.Path;Name=$w.Name;Command=([string]$w.Command+' '+[string]$w.Script).Trim();Path=(PathOf $w.Command);Enabled=($bindings.Count -gt 0);Principal='WMI消费者上下文';Extra=($bindings|ConvertTo-Json -Depth 4 -Compress)}
 }
 $packages=@() # Installer discovery is not part of automatic incident response.
 $raw=[pscustomobject]@{Host=$hostinfo;NetworkObservation=$networkObservation;DebugPrivilege=$debugPrivilege;Processes=@($processes);TCP=@($tcp);UDP=@($udp);DNS=@($dns);Persistence=@($persist);WMI=@($wmi);Users=@($users);Admins=@($admins);Defender=@($defender);Exclusions=@($exclusions);Detections=@($detections);Events=@($events);Modules=@($modules);RecentFiles=@($recent);Packages=@($packages);InstallEvents=@($script:packageEvents);Memory=@($memory);ExecutionHistory=@($history);Journals=@($journals);Crashes=@($crashes);Coverage=$coverage.ToArray()}
 $raw|Add-Member ImageIntegrity @($imageIntegrity) -Force
 $null=Stage '启动目标与全部已加载模块验证' {Verify-IRCriticalTargets $raw}
 # Critical signatures have their own verification pass. Optional files cannot displace them.
 $inv=@(Stage '深度文件与网络线索' {Get-IRInvestigationEvidence $raw})
 $raw|Add-Member -NotePropertyName Investigation -NotePropertyValue $(if($inv.Count){$inv[0]}else{$null}) -Force
 $g=@(Stage '驻留目标与加载目录优先检查' {Get-GeneralEvidence $raw})
 $raw | Add-Member -NotePropertyName General -NotePropertyValue $(if($g.Count){$g[0]}else{$null}) -Force
 $runtime=@(Stage '运行实例与外联追查' {Get-IRRuntimeEvidence $raw})
 $raw|Add-Member -NotePropertyName Runtime -NotePropertyValue $(if($runtime.Count){$runtime[0]}else{$null}) -Force
 $raw | Add-Member -NotePropertyName Files -NotePropertyValue @($cache.Values) -Force
 $raw.Coverage=$coverage.ToArray()
 Save 'evidence.json' $raw
}
Write-Output '研判：关联文件、进程、网络、持久化与日志'
if($InputEvidence -and $raw.Files){foreach($m in $raw.Files){$cache[$m.Path]=$m}}
if($InputEvidence -and !$raw.General){Gap '自动追查目标' '旧证据未包含目标目录及脚本内容；回放不读取分析电脑。'}
$ioc=@{SHA256=@();IP=@();Domain=@()}
if($IocFile){$ioc=Get-Content -LiteralPath $IocFile -Raw -Encoding UTF8|ConvertFrom-Json}
Save 'ioc-used.json' $ioc
foreach($r in @(IR-References $raw)){$null=Meta $r.Path}
# 优先验证可写目录和实际加载DLL，避免系统驱动先耗尽预算。
foreach($h in $raw.ExecutionHistory){$null=Meta $h.Path}
foreach($mrow in $raw.Modules){if($mrow.Path -notmatch '(?i)^[A-Z]:\\Windows\\'){$null=Meta $mrow.ProcessPath;$null=Meta $mrow.Path}}
foreach($s in $raw.Persistence){if(WritableHint $s.Path){$null=Meta $s.Path}}
foreach($p in $raw.Processes){if(WritableHint $p.Path){$null=Meta $p.Path}}
$recentPriority=@($raw.RecentFiles|Sort-Object ModifiedUtc -Descending|Select-Object -First 40)
foreach($r in $recentPriority){$null=Meta $r.Path}
$pmap=@{};foreach($p in $raw.Processes){$pmap[[string]$p.Pid]=$p}
foreach($p in $raw.Processes){
 $m=Meta $p.Path
 $parent=$pmap[[string]$p.ParentPid]
 if($parent -and $parent.StartUtc -and $p.StartUtc -and [datetime]$parent.StartUtc -le [datetime]$p.StartUtc){Edge ("PID $($parent.Pid) $($parent.Name)") ("PID $($p.Pid) $($p.Name)") '父子进程候选' "快照 PPID=$($p.ParentPid)，父进程启动不晚于子进程；PID重用仍可能发生" '候选关联'}
 if($p.Path){Edge $p.Path ("PID $($p.Pid) $($p.Name)") '映像路径' 'Win32_Process.ExecutablePath' '采集事实'}
 if($m -and $m.Exists -and (WritableHint $p.Path) -and $m.Signature -in @('NotSigned','HashMismatch','NotTrusted') -and $p.Path -ne $IRLauncher){Finding '中' '用户可写位置的未验证签名进程' ("进程 PID=$($p.Pid)") $p.Path ("签名=$($m.Signature); 命令=$($p.Command)") '核对安装来源、哈希和业务用途；未签名本身不能定性。'}
 if($p.Command -match '(?i)(stratum\+tcp|stratum\+ssl|--donate-level|--coin\s+monero|xmrig)'){Finding '高' '挖矿协议/参数线索' ("进程 PID=$($p.Pid)") $p.Path $p.Command '确认是否授权挖矿；关联连接、启动项及父进程追查投放源。'}
 if($p.Command -match '(?i)(-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|DownloadString\s*\(|FromBase64String\s*\(|https?://.+\.(hta|ps1)\b)'){Finding '高' '脚本下载/编码执行线索' ("进程 PID=$($p.Pid)") $p.Path $p.Command '保全命令行和4104/Sysmon日志；授权运维也可能命中。'}
  if($parent -and $parent.StartUtc -and $p.StartUtc -and [datetime]$parent.StartUtc -le [datetime]$p.StartUtc -and $parent.Name -match '^(winword|excel|outlook|powerpnt)\.exe$' -and $p.Name -match '^(powershell|pwsh|cmd|mshta|wscript|cscript)\.exe$'){Finding '高' 'Office拉起脚本解释器候选' ("进程 PID=$($p.Pid); 父进程=$($parent.Pid)") $p.Path $p.Command '结合ProcessGuid与文档来源核实钓鱼入口；快照父PID不足以单独确认攻击。'}
}
foreach($c in $raw.TCP){
 $p=$pmap[[string]$c.Pid]
 if($p){Edge ("PID $($p.Pid) $($p.Name)") ("$($c.RemoteAddress):$($c.RemotePort)") 'TCP端点' ("状态=$($c.State);本地=$($c.LocalAddress):$($c.LocalPort);采集时PID对应，存在快照竞态") '快照关联'}
 if($c.RemoteAddress -in $ioc.IP){Finding '高' '自定义IP IOC命中' ("TCP PID=$($c.Pid)") $c.RemoteAddress ("端口=$($c.RemotePort);状态=$($c.State)") '核实IOC时效性和归属；不能仅凭IP认定感染。'}
}
foreach($s in $raw.Persistence){
 $m=Meta $s.Path
 if($s.Path){Edge ($s.Kind+': '+$s.Location+' ['+$s.Name+']') $s.Path '配置指向文件' ("Command=$($s.Command);Enabled=$($s.Enabled);Principal=$($s.Principal)") '配置事实，不证明已执行'}
  $expanded=if($InputEvidence){[string]$s.Command}else{[Environment]::ExpandEnvironmentVariables([string]$s.Command)}
 $refs=[regex]::Matches($expanded,'(?i)"(?<p>[a-z]:\\[^"\r\n]+\.(?:exe|dll|sys|ps1|vbs|js|hta|bat|cmd))"|(?<p>[a-z]:\\[^\s",;]+\.(?:exe|dll|sys|ps1|vbs|js|hta|bat|cmd))')
 foreach($ref in $refs){$path=$ref.Groups['p'].Value;if($path -ne $s.Path){$null=Meta $path;Edge ($s.Kind+': '+$s.Location+' ['+$s.Name+']') $path '命令参数引用文件' '参数静态提取；不证明文件已执行，也不解析编码命令或脚本内部动态路径' '配置线索'}}
 $reasons=@()
 if($s.Path -and (WritableHint $s.Path) -and $m -and $m.Exists -and $m.Signature -in @('NotSigned','HashMismatch','NotTrusted')){$reasons+='可写目录+签名未通过'}
  if($s.Path -and (WritableHint $s.Path) -and $m -and $m.Exists -eq $false){Finding '低' '启动目标不存在或不可读' ($s.Kind+': '+$s.Location+' 值/名称='+$s.Name) $s.Path ('Command='+$s.Command+';Enabled='+$s.Enabled+';'+$m.Error) '核实是否为软件卸载残留或权限限制；此项不证明恶意持久化。'}
 if($s.Kind -match 'Image File Execution Options|SilentProcessExit'){$reasons+='映像劫持/退出监控配置（也可能是调试工具）'}
 if($s.Command -match '(?i)(-(enc|encodedcommand)\s|DownloadString|FromBase64String|stratum\+|mshta.+https?://)'){$reasons+='下载/编码/挖矿参数'}
 if($s.Kind -eq 'Winlogon' -and $s.Command -notmatch '^(?i)(explorer\.exe|C:\\Windows\\system32\\userinit\.exe,?)$'){$reasons+='非默认Winlogon配置'}
 if($s.Kind -eq 'AppInit/Load'){$reasons+='全局DLL/用户加载配置'}
 if($reasons.Count){Finding '中' '持久化位置需核实' ($s.Kind+': '+$s.Location+' 值/名称='+$s.Name) $s.Path (($reasons -join '; ')+';Command='+$s.Command+';Enabled='+$s.Enabled+';Principal='+$s.Principal+';'+$s.Extra) '人工核实后处置此精确值/任务/服务及目标文件；保留备份、检查依赖和重启复查。本工具不执行清理。'}
 if($s.Kind -eq 'Service' -and $s.Command -match '^[^"]+\s.+\.exe\b' -and $s.Command -notmatch '^"'){Finding '低' '服务路径未加引号' $s.Location $s.Path $s.Command '属于配置风险；需额外验证目录ACL与实际可利用性，不代表已有木马。'}
}
foreach($w in $raw.WMI){
 if($w.Class -eq '__FilterToConsumerBinding'){Edge $w.Filter $w.Consumer 'WMI绑定' $w.Path '配置事实'}
 if($w.Class -match 'EventConsumer'){Finding '中' 'WMI永久事件消费者' $w.Path (PathOf $w.Command) ($w.Command+' '+$w.Script) '核对Filter→Binding→Consumer三处对象及业务归属；root/subscription 中精确对象见原始证据。'}
}
foreach($mrow in $raw.Modules){
 $m=Meta $mrow.Path; $exe=Meta $mrow.ProcessPath
 Edge ("PID $($mrow.Pid)") $mrow.Path '加载模块' '进程模块快照：不证明DLL恶意，也不证明加载搜索顺序' '采集事实'
 if($m -and $exe -and $m.Signature -in @('NotSigned','HashMismatch','NotTrusted') -and $exe.Signature -eq 'Valid' -and (Split-Path $mrow.Path) -eq (Split-Path $mrow.ProcessPath) -and ($m.HiddenParent -or $m.Signature -eq 'HashMismatch')){
  Finding '中' 'DLL侧加载候选' ("PID=$($mrow.Pid);宿主=$($mrow.ProcessPath)") $mrow.Path ("有效签名宿主加载同目录未验证签名DLL，并存在隐藏目录或摘要不符；DLL签名=$($m.Signature);隐藏目录=$($m.HiddenParent)") '结合精确启动配置、内存和历史事件核实；合法插件不能只因未签名而被定性。'
 }
 if($m -and $m.Signature -eq 'HashMismatch'){Finding '高' '已加载模块签名摘要不符' ('PID='+$mrow.Pid) $mrow.Path '进程实际加载的文件签名摘要校验失败；不依据目录位置放行。' '保留该模块、宿主实例和启动配置证据；不将系统宿主当作恶意文件处置。'}
}
# Driver findings use signature, path, installation evidence and state in general.ps1.
foreach($e in $raw.Events){
 $d=$e.Data; $proof=$e.Log+'#'+$e.RecordId+' UTC='+$e.TimeUtc
 if($e.Log -match 'Sysmon'){
  if($e.Id -eq 1){Edge ([string]$d.ParentProcessGuid+' '+$d.ParentImage) ([string]$d.ProcessGuid+' '+$d.Image) '历史进程创建' $proof 'ProcessGuid关联事实'}
  if($e.Id -eq 3){Edge ([string]$d.ProcessGuid+' '+$d.Image) ($d.DestinationIp+':'+$d.DestinationPort) '历史网络连接' $proof 'ProcessGuid关联事实'}
  if($e.Id -eq 11){Edge ([string]$d.ProcessGuid+' '+$d.Image) $d.TargetFilename '历史文件创建' $proof '事件事实'}
  if($e.Id -in @(12,13,14)){Edge ([string]$d.ProcessGuid+' '+$d.Image) $d.TargetObject '历史注册表操作' $proof '事件事实'}
  if($e.Id -eq 7){Edge ([string]$d.ProcessGuid+' '+$d.Image) $d.ImageLoaded '历史模块加载' $proof '事件事实'}
   if($e.Id -in @(8,25)){Finding '高' '远程线程/进程篡改事件' $proof $(if($e.Id -eq 25){$d.Image}else{$d.TargetImage}) (ConvertTo-Json $d -Compress) '授权调试、安全软件也可能命中，结合源/目标路径、签名与GUID核实。'}
 }
 if($e.Id -in @(1102,104,5001)){Finding '高' '审计/防护变化事件' $proof '' (ConvertTo-Json $d -Compress) '核对运维窗口；单独的清日志/防护关闭事件不足以认定入侵。'}
 if($e.Id -eq 4624 -and [string]$d.LogonType -in @('3','10')){Edge $d.IpAddress ($d.TargetDomainName+'\'+$d.TargetUserName) ('登录类型 '+$d.LogonType) $proof '登录事实，不证明横向入侵'}
 if($e.Id -in @(4697,4698,4702,4720,4732,7045)){Finding '低' '账户/任务/服务变更记录' $proof '' (ConvertTo-Json $d -Compress) '按时间窗口和操作者核实是否授权变更；与落地、执行证据互证。'}
 if($e.Id -eq 4104 -and (IR-ScriptExecutionSignal $d.ScriptBlockText $d.Path)){Finding '中' '历史脚本下载/挖矿线索' $proof $d.Path $d.ScriptBlockText '语法树含实际命令调用，非仅字符串提及；可能是授权运维，片段日志仍不证明执行成功。'}
}
foreach($r in $raw.RecentFiles){
 $matchesPersist=@($raw.Persistence|Where-Object {$_.Path -and $_.Path -eq $r.Path})
 $matchesProcess=@($raw.Processes|Where-Object {$_.Path -and $_.Path -eq $r.Path})
 if($matchesPersist.Count -or $matchesProcess.Count){$null=Meta $r.Path; Edge $r.Path $r.CreatedUtc '文件系统创建时间' '文件时间戳可伪造，不等同真实投放时间' '时间线索'}
}
foreach($m in @($cache.Values)){if($m.SHA256 -and $m.SHA256 -in $ioc.SHA256){Finding '高' '自定义SHA256 IOC精确命中' 'SHA256='+$m.SHA256 $m.Path '采集文件哈希与提供的IOC完全相等' '确认IOC来源与样本恶意性；保全证据后由人工处置。'}}
foreach($d in $raw.DNS){foreach($domain in $ioc.Domain){if($d.Entry -eq $domain -or $d.Entry.EndsWith('.'+$domain,[StringComparison]::OrdinalIgnoreCase)){Finding '中' '自定义域名IOC命中' 'DNS缓存（不含进程归属）' $d.Entry ([string]$d.Data) '核实时效性；DNS缓存不能证明连接成功或对应某进程。'}}}
foreach($d in $raw.Detections){if(!$d.ThreatID){continue};Finding '高' 'Defender历史检测（可能已处置）' ('ThreatID='+$d.ThreatID) ($d.Resources -join ';') ('Initial='+$d.InitialDetectionTime+';ActionSuccess='+$d.ActionSuccess) '历史告警不等于当前活跃感染。保留资源路径，结合当前文件/进程与事件复核。'}
$transient=@(Get-TransientExecutions $raw ([pscustomobject]@{Files=@($cache.Values)}))
foreach($t in $transient){Finding $t.Severity $t.Conclusion ('History: '+$t.Path) $t.Path ('UserAssist='+$t.Launch.TimeUtc+'；USN删除='+$t.Deletion.TimeUtc+'；间隔='+$t.DeleteAfterSeconds+'秒；'+$t.Limit) '查看已保留的启动/删除/崩溃时间线；不能凭时间关联清理系统服务。'}
foreach($m in $raw.Memory|Where-Object {$_.IdentityMatched -and $_.Hits.Count}){Finding '中' '非映像可执行内存异常' ('Memory: PID='+$m.Pid) $m.Path ($m.Hits|ConvertTo-Json -Depth 5 -Compress) '只读定位到内存区域与线程；合法动态代码也可能命中，不将宿主EXE列为清理目标。'}
Gap '检测边界' '不进行杀毒/删除/隔离/结束进程/服务变更；不上传样本。内存仅检查非映像PE头与线程起点，文件变更仅查询已有USN日志；无内核可信校验、离线磁盘取证、完整浏览器/邮件/IIS/数据库/EDR日志。无法保证发现所有病毒。签名检查可能由Windows验证组件按系统策略联网。'
Gap '文件验证预算' "关键启动/加载对象独立180秒验证；可选磁盘候选最多1600哈希/2000验签，单文件512MB。实际哈希 $hashCount、验签 $signatureCount。短路径别名按同一物理路径缓存。未检查/UnknownError 不等于无签名；文件读取与进程快照存在竞态。"
$result=[pscustomobject]@{Host=$raw.Host;DurationSeconds=[math]::Round(((Get-Date)-$started).TotalSeconds,2);Findings=$findings.ToArray();Edges=$edges.ToArray();Files=@($cache.Values);Coverage=$coverage.ToArray();Summary='自动关联取证报告；所有启发式命中需人工核实，不构成全机无感染证明。';InputEvidence=$InputEvidence}
$runtimeCases=@(Get-IRRuntimeCases $raw @($cache.Values))
$generalCases=@($runtimeCases)+@(Get-GeneralCases $raw @($cache.Values)|Where-Object {$_.Target -notin $runtimeCases.Target})
$result|Add-Member -NotePropertyName GeneralCases -NotePropertyValue $generalCases
$result|Add-Member -NotePropertyName TransientExecutions -NotePropertyValue $transient
Save 'analysis.json' $result
$raw | Add-Member -NotePropertyName Files -NotePropertyValue @($cache.Values) -Force
$raw | Add-Member -NotePropertyName Coverage -NotePropertyValue $coverage.ToArray() -Force
Save 'evidence.json' $raw
$triage=& (Get-IRScript 'triage.ps1') -RawEvidence $raw -Analysis $result -Output $Output -Live:(!$InputEvidence)
Add-IRCaseEvidence $triage.Cases $raw
Save 'response-plan.json' $triage
$network=Get-IRIndependentNetwork $raw
$network|Add-Member Pivots @(Get-IRNetworkPivots $raw $network)
$network|Add-Member CaseEvidence @($triage.Cases|ForEach-Object {[pscustomobject]@{Case=$_.Id;Target=$_.Target;Network=$_.NetworkEvidence}})
Save 'network-evidence.json' $network
Save 'persistence-pivots.json' @($raw.General.PersistencePivots|Where-Object {$_})
& (Get-IRScript 'report.ps1') -RawEvidence $raw -Analysis $result -Output $Output -Hours $Hours
$manifest=@(Get-ChildItem -LiteralPath $Output -File|Where-Object Name -ne 'manifest.json'|ForEach-Object {[pscustomobject]@{Name=$_.Name;Size=$_.Length;SHA256=(HashFile $_.FullName)}})
Save 'manifest.json' $manifest
Write-Output "完成：$Output\report.html"
