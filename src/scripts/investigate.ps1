# Read-only host investigation. No inspected code is executed and no endpoint is contacted.
function IR-ResolveFile([string]$text,[string]$base='') {
 if(!$text -or $text.IndexOf([char]0) -ge 0){return ''};$s=[Environment]::ExpandEnvironmentVariables($text.Trim().Trim('"'))
 $s=$s -replace '^\\\?\?\\','' -replace '^\\SystemRoot', $env:SystemRoot
 if($s -match '^(?i)System32\\'){$s=Join-Path $env:SystemRoot $s}
 if($s -notmatch '^[a-zA-Z]:\\'){
  if($s -match '[\\/]' -and $base){$s=Join-Path $base $s}
  elseif($s -notmatch '[\\/]'){$s=Join-Path ($env:SystemRoot+'\System32') $s}
 }
 if($s -match '^[a-zA-Z]:\\'){return $s};return ''
}
function IR-RegistryChildren([string]$root) {
 try{$parent=Get-Item -LiteralPath $root -ErrorAction Stop;$names=$parent.GetSubKeyNames()}catch{Gap ('注册表枚举 '+$root) $_.Exception.Message;return}
 foreach($name in $names){try{Get-Item -LiteralPath ($root+'\'+$name) -ErrorAction Stop}catch{Gap ('注册表子键 '+$root+'\'+$name) $_.Exception.Message}}
}
function Get-IRTaskStorage($task) {
 $relative=($task.TaskPath+$task.TaskName).TrimStart('\');$base='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
 $tree=$base+'\Tree\'+$relative;$guid='';$key=$null
 try{$key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($tree);if($key){$value=[string]$key.GetValue('Id');$parsed=[guid]::Empty;if([guid]::TryParse($value,[ref]$parsed)){$guid=$parsed.ToString('B')}}}catch{Gap ('任务索引 '+$relative) $_.Exception.Message}finally{if($key){$key.Close()}}
 $root=$env:SystemRoot+'\System32\Tasks\';$file=[IO.Path]::GetFullPath((Join-Path $root $relative));if(!$file.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){$file=''}
 [pscustomobject]@{TaskFile=$file;Tree=('HKEY_LOCAL_MACHINE\'+$tree);Guid=$guid;IdKey=if($guid){'HKEY_LOCAL_MACHINE\'+$base+'\Tasks\'+$guid}else{''}}
}
function Get-IRExtraPersistence {
 $root='Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services'
 foreach($k in IR-RegistryChildren $root){
  try {
   $start=$k.GetValue('Start');$type=$k.GetValue('Type');$cmd=[string]$k.GetValue('ImagePath');$name=$k.PSChildName
   $mode=switch($start){0{'Boot'}1{'System'}2{'Auto'}3{'Manual'}4{'Disabled'}default{'Unknown'}}
   $kind=if(([int]$type -band 3) -ne 0){'Driver'}else{'Service'}
   if($cmd){[pscustomobject]@{Kind=$kind;Location=$k.Name;Name=$name;Command=$cmd;Path=(IR-ResolveFile (PathOf $cmd));Enabled=($null -ne $start -and $start -ne 4);Principal=[string]$k.GetValue('ObjectName');StartMode=$mode;Extra=('ImagePath; Start='+$start+'; Type='+$type+'; DisplayName='+$k.GetValue('DisplayName'));RegistryStart=$start;RegistryType=$type}}
   foreach($sub in @($k.Name,($k.Name+'\Parameters'))){
    $key=Get-Item -LiteralPath ('Registry::'+$sub) -ErrorAction SilentlyContinue
    if($key -and $key.GetValue('ServiceDll')){$dll=[string]$key.GetValue('ServiceDll');[pscustomobject]@{Kind='ServiceDll';Location=('Registry::'+$sub);Name='ServiceDll';ServiceName=$name;Command=$dll;Path=(IR-ResolveFile $dll);Enabled=($null -ne $start -and $start -ne 4);Principal=[string]$k.GetValue('ObjectName');StartMode=$mode;Extra=('Service='+$name+'; Start='+$start+'; Type='+$type);RegistryStart=$start;RegistryType=$type}}
   }
  } catch {Gap ('服务注册表 '+$k.Name) $_.Exception.Message}
 }
 $fixed=@(
  @('SYSTEM\CurrentControlSet\Control\Lsa',@('Authentication Packages','Security Packages','Notification Packages'),'LSA'),
  @('SYSTEM\CurrentControlSet\Control\Lsa\OSConfig',@('Security Packages'),'LSA'),
  @('SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls',@(),'AppCertDlls'),
  @('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32',@(),'Drivers32'),
  @('SOFTWARE\Microsoft\NetSh',@(),'Netsh helper'))
 foreach($entry in $fixed){foreach($v in @(RegValues ('Registry::HKEY_LOCAL_MACHINE\'+$entry[0]) $entry[1] $entry[2])){
  if($v.Kind -eq 'LSA'){
   $key=Get-Item -LiteralPath $v.Location
   foreach($part in @($key.GetValue($v.Name))){$value=[string]$part;if(!$value){continue};if($value -notmatch '\.dll$'){$value+='.dll'};$o=$v.PSObject.Copy();$o.Command=$value;$o.Path=IR-ResolveFile $value;$o;}
  }else{$v.Path=IR-ResolveFile $v.Command;$v}
 }}
 foreach($entry in @(@('SYSTEM\CurrentControlSet\Control\Print\Monitors','Driver','Print monitor'),@('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify','DLLName','Winlogon Notify'))){
  $root='Registry::HKEY_LOCAL_MACHINE\'+$entry[0];if(Test-Path -LiteralPath $root){foreach($key in IR-RegistryChildren $root){foreach($v in @(RegValues $key.PSPath @($entry[1]) $entry[2])){$v.Path=IR-ResolveFile $v.Command;$v}}}
 }
 $bases=@('Registry::HKEY_LOCAL_MACHINE\SOFTWARE','Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node')
 foreach($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()){if($sid -match '^S-1-5-21-[\d-]+$'){$bases+=('Registry::HKEY_USERS\'+$sid+'\Software')}}
 foreach($b in $bases){
  $root=$b+'\Microsoft\Active Setup\Installed Components';if(Test-Path -LiteralPath $root){foreach($key in IR-RegistryChildren $root){RegValues $key.PSPath @('StubPath') 'Active Setup'}}
  if($b -match 'HKEY_USERS'){
   foreach($suffix in @('Classes\CLSID','Classes\Wow6432Node\CLSID')){
    $root=$b+'\'+$suffix;if(!(Test-Path -LiteralPath $root)){continue};$n=0
    foreach($key in IR-RegistryChildren $root){if(++$n -gt 1500){Gap '用户COM范围' '超过1500个CLSID；后续未检查';break}
     foreach($type in @('InprocServer32','LocalServer32')){foreach($v in @(RegValues ($key.PSPath+'\'+$type) @() 'User COM')){if($v.Name){continue};$v.Path=IR-ResolveFile (PathOf $v.Command);$v.Enabled=$null;$v.Extra='用户级COM注册；未证明有调用方或已触发';$v}}
    }
   }
  }
 }
 foreach($t in Get-ScheduledTask){foreach($a in $t.Actions){if(!$a.ClassId){continue}
  foreach($b in $bases){$key=$b+'\Classes\CLSID\'+$a.ClassId+'\InprocServer32';foreach($v in @(RegValues $key @() 'Task')){if($v.Name){continue};$v.Name=$t.TaskName;$v.Path=IR-ResolveFile $v.Command;$v.Extra='COM handler '+$a.ClassId+'; Registry='+$key;$v.Location=$t.TaskPath+$t.TaskName;$v.Enabled=([string]$t.State -ne 'Disabled');$v.Principal=$t.Principal.UserId;$v}}
 }}
}
function Get-IRDeepFiles($raw,[int]$Hours,[string[]]$RootOverride=@()) {
 Initialize-IRFileProbe
 $queues=New-Object 'Collections.Generic.List[object]';$seen=@{};$timer=[Diagnostics.Stopwatch]::StartNew();$dirs=0;$files=0;$heads=0;$scopeCounts=@{};$ownHashes=@{}
 $roots=@($env:ProgramData)
 foreach($u in Get-CimInstance Win32_UserProfile){if($u.LocalPath){$roots+=@(($u.LocalPath+'\AppData\Roaming'),($u.LocalPath+'\AppData\Local'),($u.LocalPath+'\Downloads'),($u.LocalPath+'\Desktop'))}}
 $roots+=@(($env:SystemRoot+'\System32'),($env:SystemRoot+'\SysWOW64'),$env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)})
 foreach($p in @($raw.Persistence.Path)+@($raw.Processes.Path)){if($p -match '^[a-z]:\\'){$roots+=Split-Path $p}}
 if($RootOverride.Count){$roots=$RootOverride}
 foreach($r in $roots|Where-Object {$_}|ForEach-Object {[YingJiFile.Probe]::Canonical($_)}|Select-Object -Unique){$q=New-Object 'Collections.Generic.Queue[object]';$q.Enqueue(@($r,0));$queues.Add(@{Root=$r;Queue=$q});$scopeCounts[$r]=@{Directories=0;Candidates=0;ContentReads=0}}
 $cut=[datetime]::UtcNow.AddHours(-$Hours)
 $turn=0
 while(@($queues|Where-Object {$_.Queue.Count}).Count -and $dirs -lt 30000 -and $files -lt 40000 -and $timer.Elapsed.TotalSeconds -lt 120){
  $scope=$queues[$turn%$queues.Count];$turn++;$q=$scope.Queue;if(!$q.Count){continue}
  $item=$q.Dequeue();$dir=[YingJiFile.Probe]::Canonical([string]$item[0]);$depth=[int]$item[1];if($seen.ContainsKey($dir)){continue};$seen[$dir]=$true;$dirs++;$scopeCounts[$scope.Root].Directories++
  if($dir.StartsWith($Output,[StringComparison]::OrdinalIgnoreCase)){continue}
  try{$directoryInfo=New-Object IO.DirectoryInfo($dir);$directoryRecent=($directoryInfo.CreationTimeUtc -ge $cut -or $directoryInfo.LastWriteTimeUtc -ge $cut);$hidden=IR-HiddenParent (Join-Path $dir '__read_only_name__');$children=$directoryInfo.GetFileSystemInfos()}catch{Gap ('深度目录 '+$dir) $_.Exception.Message;continue}
  foreach($f in $children){
   if($timer.Elapsed.TotalSeconds -ge 120){break}
   if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){continue}
   if($f -is [IO.DirectoryInfo]){
    if($depth -lt 10 -and $f.FullName -notmatch '(?i)\\Windows\\(WinSxS|Installer|servicing|assembly|SoftwareDistribution)(\\|$)' -and $f.Name -notin @('node_modules','.git','Cache','CacheStorage','Code Cache','ReportArchive','ReportQueue')){$q.Enqueue(@($f.FullName,$depth+1))};continue
   }
   $recent=($f.CreationTimeUtc -ge $cut -or $f.LastWriteTimeUtc -ge $cut)
   # Only byte-identical embedded scripts in a generated report may be omitted. A modified script or another file in the report directory still gets scanned.
   if($f.Extension -eq '.ps1' -and $directoryInfo.Name -match '^IR-\d{8}-\d{6}-[a-f0-9]{8}$' -and [IO.File]::Exists((Join-Path $dir 'manifest.json'))){
    $name=if($f.Name -eq 'collector.ps1'){'engine.ps1'}else{$f.Name}
    if($IRCode.ContainsKey($name)){try{if(!$ownHashes.ContainsKey($name)){$ownHashes[$name]=[YingJiRuntime.Payload]::GetHash($name)};if((Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash -eq $ownHashes[$name]){continue}}catch{}}
   }
   # File timestamps can be preserved by extraction or changed by attackers. They never exempt content inspection.
   $ext=$f.Extension;$exe=$ext -match '^(?i)\.(exe|dll|sys|scr|com|ps1|vbs|js|hta|bat|cmd)$';$disguised=$false;$shape=$null
   if(!$exe -and $ext -notmatch '^(?i)\.(winmd|mui|olb|ocx|cpl|ax|acm|tsp|efi|pyd|node|fon|tlb)$' -and $f.Length -ge 96 -and $heads -lt 50000){
    $heads++;$scopeCounts[$scope.Root].ContentReads++;$shape=Read-ContentShape $f.FullName;$disguised=$shape.Kind -in @('DisguisedPE','EncodedPE','DisguisedZipWithCode')
   }
   if($exe -or $disguised){$files++;$scopeCounts[$scope.Root].Candidates++;[pscustomobject]@{Path=$f.FullName;Size=$f.Length;CreatedUtc=$f.CreationTimeUtc.ToString('o');ModifiedUtc=$f.LastWriteTimeUtc.ToString('o');HiddenDirectory=$hidden;DisguisedPE=($shape.Kind -eq 'DisguisedPE');ContentAnomaly=$disguised;ContentShape=$shape;Recent=$recent;DirectoryRecent=$directoryRecent};if($files -ge 40000){break}}
  }
 }
 $remaining=0;foreach($s in $queues){$remaining+=$s.Queue.Count}
 Gap '深度文件范围' ('各根目录轮转扫描，覆盖所有用户AppData/下载/桌面、ProgramData/Program Files、System32/SysWOW64及Windows非标准目录；深度10、120秒、30000目录/40000文件/50000内容头上限；实际目录='+$dirs+'，候选='+$files+'，头检查='+$heads+'，剩余目录='+$remaining+'。已保留逐根目录计数；重解析点和常规缓存/组件库跳过；不是全盘扫描。')
 $script:irFileScopeCounts=$scopeCounts
}
function IR-TextIndicators([string]$text,[string]$source,[string]$kind) {
 $seen=@{};$count=0
 foreach($m in [regex]::Matches($text,'(?i)\b(?:https?|wss?|stratum\+(?:tcp|ssl)|tcp|udp)://[a-z0-9][a-z0-9.\-\[\]:]*(?:/[^\s"''<>\x00-\x20]{0,240})?|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])')){
  $value=$m.Value.TrimEnd('.',',',')',';');if($seen.ContainsKey($value)){continue};$seen[$value]=$true
  if($value -match '://'){$uri=$null;if(![uri]::TryCreate($value,[UriKind]::Absolute,[ref]$uri) -or !$uri.Host -or $uri.Host -notmatch '\.'){continue}}
  if($value -match '^\d'){ $addr=$value -replace ':\d+$','';$ip=$null;if(![Net.IPAddress]::TryParse($addr,[ref]$ip) -or !(IR-PublicAddress $addr)){continue}}
  if(++$count -gt 80){break};[pscustomobject]@{Value=$value;Source=$source;Kind=$kind;Assessment='静态字符串候选；不证明发生连接或为C2'}
 }
}
function Get-IRStaticNetwork($paths) {
 $count=0;$seen=@{};$timer=[Diagnostics.Stopwatch]::StartNew()
 foreach($path in $paths|Where-Object {$_}|Select-Object -Unique){
  if($count -ge 120 -or $timer.Elapsed.TotalSeconds -gt 15){Gap '静态网络提取' '达到120文件/15秒上限';break}
  if($seen.ContainsKey($path)){continue};$seen[$path]=$true;$count++;$f=$null
  try{
   $f=[IO.File]::Open($path,'Open','Read','ReadWrite');$b=New-Object byte[] ([int][math]::Min($f.Length,4MB));$n=$f.Read($b,0,$b.Length)
   $contentKind='文件内容';$shape=Read-ContentShape $path
   if($shape.Kind -eq 'EncodedPE' -and $shape.XorKey.Count){
    if(!('YingJiStatic.Decode' -as [type])){throw '内嵌解码探测类型未加载'}
    [YingJiStatic.Decode]::Xor($b,[byte[]]$shape.XorKey);$contentKind='循环XOR还原后的静态内容（未执行）'
   }
   # Authenticode certificate tables contain CA/CRL/OCSP URLs, not program C2 configuration.
   if($n -gt 256 -and $b[0] -eq 77 -and $b[1] -eq 90){
    $pe=[BitConverter]::ToInt32($b,60)
    if($pe -ge 64 -and $pe+24+152 -lt $n){$magic=[BitConverter]::ToUInt16($b,$pe+24);$dd=if($magic -eq 523){112}else{96};$at=$pe+24+$dd+32
     $cert=[BitConverter]::ToUInt32($b,$at);$len=[BitConverter]::ToUInt32($b,$at+4)
     if($cert -gt 0 -and $cert -lt $n){[Array]::Clear($b,[int]$cert,[int][math]::Min($len,$n-$cert))}
    }
   }
   $text=[Text.Encoding]::ASCII.GetString($b,0,$n);IR-TextIndicators $text $path ($contentKind+' ASCII')
   foreach($offset in @(0,1)){if($n -gt $offset){IR-TextIndicators ([Text.Encoding]::Unicode.GetString($b,$offset,($n-$offset)-(($n-$offset)%2))) $path ($contentKind+' UTF16')}}
   if($f.Length -gt 4MB){Gap ('静态内容 '+$path) '只读取前4MiB；加密/压缩内容不在覆盖范围'}
  }catch{Gap ('静态内容 '+$path) $_.Exception.Message}finally{if($f){$f.Dispose()}}
 }
}
function Get-IRInvestigationEvidence($raw) {
 $deep=@(Get-IRDeepFiles $raw $Hours)
 # Prioritize objective anomalies before ordinary recent installers consume signature budget.
 foreach($f in $deep|Sort-Object @{e={if($_.ContentAnomaly -or $_.DisguisedPE){0}elseif($_.HiddenDirectory){1}elseif($_.DirectoryRecent -and $_.Path -match '(?i)\\Users\\[^\\]+\\AppData\\Roaming\\'){2}elseif($_.DirectoryRecent -and $_.Path -match '(?i)\\(Users|ProgramData)\\'){3}elseif($_.DirectoryRecent){4}else{5}}},@{e={$_.CreatedUtc};Descending=$true}|Select-Object -First 160){$null=Meta $f.Path}
 $paths=@($raw.Persistence.Path)+@($raw.Processes.Path)+@($raw.Modules.Path)
 foreach($p in $paths|Where-Object {$_}|Select-Object -Unique){$null=Meta $p}
 $suspects=@($cache.Values|Where-Object {$_.Exists -and ($_.Signature -eq 'HashMismatch' -or ($_.Signature -in @('NotSigned','NotTrusted') -and $_.HiddenParent))}|ForEach-Object {$_.Path})
 $suspects=@($deep|Where-Object {$_.ContentShape.Kind -eq 'EncodedPE'}|ForEach-Object {$_.Path})+@($suspects)+@($deep|Where-Object {$_.ContentShape.Kind -eq 'DisguisedZipWithCode' -or ($_.DisguisedPE -and $_.HiddenDirectory)}|ForEach-Object {$_.Path})

 $config=@();foreach($p in $suspects|Select-Object -Unique){try{$config+=@(Get-ChildItem -LiteralPath (Split-Path $p) -File -Force -ErrorAction Stop|Where-Object {$_.Extension -in @('.ini','.cfg','.conf','.json','.xml','.dat') -and $_.Length -le 1MB}|Select-Object -First 12|ForEach-Object {$_.FullName})}catch{}}
 $indicators=@(Get-IRStaticNetwork (@($suspects)+@($config)))
 return [pscustomobject]@{DeepFiles=$deep;FileScopeCounts=$script:irFileScopeCounts;StaticNetwork=$indicators;ConfigScope='仅异常文件及邻近配置；相邻配置中的地址不能直接归属木马'}
}
function Add-IRCaseEvidence($cases,$raw) {
 foreach($c in $cases){
  $paths=@($c.Target)+@($c.Files.Path)+@($c.AbnormalFiles.Path);$paths=@($paths|Where-Object {$_}|Select-Object -Unique)
  $refs=@(IR-References $raw|Where-Object {$_.Path -in $paths -and !($c.RuntimeCase -and (IR-SharedHost $_.Path))})
  $persist=@($raw.Persistence|Where-Object {$s=$_;@($refs|Where-Object {$_.Kind -eq $s.Kind -and $_.Location -eq $s.Location -and $_.Name -eq $s.Name}).Count})
  foreach($p in $persist){if(!@($c.Persistence|Where-Object {$_.Location -eq $p.Location -and $_.Name -eq $p.Name -and $_.Kind -eq $p.Kind}).Count){$c.Persistence+=@($p)}}
  $guids=@{};foreach($guid in $c.ProcessGuids){if($guid){$guids[[string]$guid]=$true}};$history=New-Object 'Collections.Generic.List[object]';$nets=New-Object 'Collections.Generic.List[object]';$files=New-Object 'Collections.Generic.List[object]';$regs=New-Object 'Collections.Generic.List[object]'
  $sys=@($raw.Events|Where-Object {$_.Log -match 'Sysmon'}|Sort-Object TimeUtc)
  foreach($e in $sys){$d=$e.Data
   if(!$c.RuntimeCase -and (($d.Image -in $paths -and !(IR-SharedHost ([string]$d.Image))) -or ($e.Id -eq 7 -and $d.ImageLoaded -in $paths))){if($d.ProcessGuid){$guids[[string]$d.ProcessGuid]=$true}}
   if(!$c.RuntimeCase -and $e.Id -eq 8 -and $d.SourceImage -in $paths -and $d.TargetProcessGUID){$guids[[string]$d.TargetProcessGUID]=$true}
  }
  # Explicit ProcessGuid edges only. Time proximity and old PID alone never create an attack chain.
  for($depth=0;$depth -lt 3;$depth++){foreach($e in $sys|Where-Object Id -eq 1){$d=$e.Data;if($d.ParentProcessGuid -and $guids.ContainsKey([string]$d.ParentProcessGuid) -and $d.ProcessGuid){$guids[[string]$d.ProcessGuid]=$true}}}
  foreach($e in $sys){$d=$e.Data;$proof=$e.Log+'#'+$e.RecordId;$owned=($d.ProcessGuid -and $guids.ContainsKey([string]$d.ProcessGuid))
   if(!$owned){continue};$history.Add($e)
   if($e.Id -eq 3){$nets.Add([pscustomobject]@{Value=($d.DestinationIp+':'+$d.DestinationPort);Domain=$d.DestinationHostname;Source=$proof;TimeUtc=$e.TimeUtc;Process=$d.Image;Identity=$d.ProcessGuid;Kind='Sysmon连接记录';Assessment='关联实例曾发生连接；未直接定性C2'})}
   if($e.Id -eq 22){$nets.Add([pscustomobject]@{Value=$d.QueryName;Domain=$d.QueryName;Source=$proof;TimeUtc=$e.TimeUtc;Process=$d.Image;Identity=$d.ProcessGuid;Kind='进程DNS查询';Assessment=('查询状态='+$d.QueryStatus+'; 结果='+$d.QueryResults+'；查询不等于连接')})}
   if($e.Id -eq 11){$files.Add([pscustomobject]@{Path=$d.TargetFilename;Source=$proof;TimeUtc=$e.TimeUtc;Process=$d.Image;Identity=$d.ProcessGuid;Relation='关联实例写入；内容是否恶意待核实'})}
   if($e.Id -in @(12,13,14)){$regs.Add([pscustomobject]@{Location=$d.TargetObject;Value=$d.Details;Source=$proof;TimeUtc=$e.TimeUtc;Process=$d.Image;Identity=$d.ProcessGuid;Relation='关联实例注册表操作；不是所有写入都用于持久化'})}
  }
  $networkRows=if($c.RuntimeCase){@($c.Connections)}else{@($raw.TCP)}
  foreach($p in $c.Processes){foreach($n in $networkRows|Where-Object {$_.Pid -eq $p.Pid -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1') -and $_.State -notin @('Listen','Bound')}){
   $names=@($raw.DNS|Where-Object Data -eq $n.RemoteAddress|ForEach-Object {$_.Entry}|Select-Object -Unique)
   $nets.Add([pscustomobject]@{Value=($n.RemoteAddress+':'+$n.RemotePort);Domain=($names -join ', ');Source=if($n.Source){$n.Source}else{'TCP快照'};TimeUtc=if($n.TimeUtc){$n.TimeUtc}else{$raw.Host.TimeUtc};Process=$p.Path;Identity=('PID='+$p.Pid+' Start='+$p.StartUtc);Kind=[string]$n.State;Assessment=('连接/尝试记录；操作状态='+$n.Status+'；DNS缓存同IP映射不证明此进程查询该域名')})
  }}
  foreach($e in $raw.Runtime.NetworkObservation.DNSEvents|Where-Object {$_ -and $_.Id -in @(3006,3008)}){
   $di=Resolve-IRDNSIdentity $e $raw.Runtime.NetworkObservation
   if(!$di.IdentityMatched){continue}
   $owners=@($c.Processes|Where-Object {[string]$_.Pid -eq [string]$di.Pid -and [datetimeoffset]$_.StartUtc -eq [datetimeoffset]$di.StartUtc -and $_.Path -eq $di.Path})
   if($owners.Count){$nets.Add([pscustomobject]@{Value=$e.Data.QueryName;Domain=$e.Data.QueryName;Source=('DNS ETW#'+$e.RecordId+' EventID='+$e.Id);TimeUtc=$e.TimeUtc;Process=$di.Path;Identity=('PID='+$di.Pid+' Start='+$di.StartUtc);Kind='进程DNS查询';Assessment=('状态='+$e.Data.QueryStatus+'；结果='+$e.Data.QueryResults+'；本窗口同类次数='+$(if($e.Count){$e.Count}else{1})+'；查询时间与该进程启动实例复核一致；查询不证明成功连接，不把DNS服务器当C2')})}
  }
  foreach($e in $raw.Events|Where-Object {$_.Log -eq 'Security' -and $_.Id -in @(5156,5157)}){
   $d=$e.Data;$app=[string]$d.Application
   # Device paths cannot be silently equated with drive paths. Preserve only exact image matches here.
   if(!$c.RuntimeCase -and $app -in $paths -and !(IR-SharedHost $app)){$nets.Add([pscustomobject]@{Value=($d.DestAddress+':'+$d.DestPort);Domain='';Source=('Security#'+$e.RecordId);TimeUtc=$e.TimeUtc;Process=$app;Identity=('PID='+$d.ProcessID);Kind=if($e.Id -eq 5157){'WFP阻止连接'}else{'WFP允许连接'};Assessment='按应用路径关联历史审核；允许不等于TCP握手成功'})}
  }
  foreach($n in $raw.Investigation.StaticNetwork|Where-Object {$_.Source -in $paths}){$nets.Add([pscustomobject]@{Value=$n.Value;Domain='';Source=$n.Source;TimeUtc='';Process='';Identity='';Kind=$n.Kind;Assessment=$n.Assessment})}
  foreach($s in $c.Persistence){foreach($n in @(IR-TextIndicators ([string]$s.Command) ($s.Location+' ['+$s.Name+']') '配置字符串')){$nets.Add($n)}}
  foreach($s in $raw.General.Scripts|Where-Object {$_.Path -in $paths -and $_.Status -eq 'Read'}){foreach($n in @(IR-TextIndicators ([string]$s.Text) $s.Path '脚本内容字符串')){$nets.Add($n)}}
  $c|Add-Member -NotePropertyName NetworkEvidence -NotePropertyValue @($nets.ToArray()|Sort-Object Kind,Value,Source -Unique) -Force
  $c|Add-Member -NotePropertyName WrittenFiles -NotePropertyValue $files.ToArray() -Force
  $c|Add-Member -NotePropertyName RegistryWrites -NotePropertyValue $regs.ToArray() -Force
  $c|Add-Member -NotePropertyName LinkedEvents -NotePropertyValue $history.ToArray() -Force
 }
}
