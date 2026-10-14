# Primary discovery unit: an observed process instance, its memory/modules and its endpoints.
function Get-IRRuntimeEvidence($raw) {
 $network=$raw.NetworkObservation
 if(!$network){$network=Get-IRNetworkObservation -directory $Output -seconds 20}
 $observed=@($network.Connections)+@($network.SocketConnections|Where-Object {$_});$samples=@($network.Samples)
 foreach($note in $network.Notes){Gap '网络观察' $note}
 Gap '网络观察范围' ($network.TraceStatus+'；'+$network.Limit)
 $after=@{};foreach($p in Get-CimInstance Win32_Process){$after[[int]$p.ProcessId]=$p}
 $identity=@{};foreach($p in $raw.Processes){$now=$after[[int]$p.Pid];$identity[[string]$p.Pid]=[bool]($now -and $p.Path -and $now.ExecutablePath -eq $p.Path -and $now.CreationDate -and $now.CreationDate.ToUniversalTime().ToString('o') -eq $p.StartUtc)}
 foreach($n in $observed){$n.IdentityMatched=[bool]$identity[[string]$n.Pid];if($n.ProcessStartUtc){$p=@($raw.Processes|Where-Object Pid -eq $n.Pid|Select-Object -First 1);$n.IdentityMatched=($n.IdentityMatched -and $p.Count -eq 1 -and $p[0].StartUtc -eq $n.ProcessStartUtc)}}
 $active=@($observed|Where-Object {$_.IdentityMatched -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')}|ForEach-Object {$_.Pid})
 foreach($e in $network.DNSEvents|Where-Object {$_ -and $_.Id -in @(3006,3008)}){$di=Resolve-IRDNSIdentity $e $network;if($di.IdentityMatched){$active+=[int]$di.Pid}}
 $memory=@($raw.Memory|Where-Object {$_.IdentityMatched -and $_.Hits.Count}|ForEach-Object {$_.Pid})
 $timer=[Diagnostics.Stopwatch]::StartNew();$checked=@{};$checks=0
 # Network/memory instances get the signature/hash budget before dormant files.
 foreach($p in $raw.Processes|Sort-Object @{e={if($_.Pid -in $active){0}elseif($_.Pid -in $memory){1}else{2}}}){
  if(!$identity[[string]$p.Pid] -or $p.Path -eq $IRLauncher -or $p.Pid -eq $PID){continue}
  if($timer.Elapsed.TotalSeconds -ge 40){Gap '运行态验证预算' '达到40秒；未验证模块不可视为正常';break}
  $null=Meta $p.Path
  $modules=@($raw.Modules|Where-Object Pid -eq $p.Pid|Sort-Object @{e={if($_.Path -notmatch '(?i)\\Windows\\(System32|SysWOW64|WinSxS)\\'){0}else{1}}})
  foreach($m in $modules){
   if($checked.ContainsKey([string]$m.Path)){continue}
   if($checks -ge 400 -or $timer.Elapsed.TotalSeconds -ge 40){break}
   $checked[[string]$m.Path]=$true;$checks++;$null=Meta $m.Path
  }
 }
 Gap '运行态验证范围' ('按外联、内存异常、其他当前进程排序；验证'+$checks+'个唯一加载模块，最多400个/40秒。Windows路径和有效签名宿主不免检。20秒TCP轮询仍可能漏掉瞬时通信，DNS ETW状态见独立网络证据。')
 return [pscustomobject]@{Connections=$observed;Samples=$samples;NetworkObservation=$network;Identity=$identity;CheckedModules=@($checked.Keys)}
}
function Get-IRRuntimeCases($raw,$files) {
 $map=@{};foreach($f in $files){if($f.Path){$map[[string]$f.Path]=$f}}
 $result=New-Object 'Collections.Generic.List[object]';$refs=@(IR-References $raw)
 foreach($p in $raw.Processes){
  if(!$p.Path -or $p.Path -eq $raw.Host.CollectorPath){continue}
  $idOK=$false;if($raw.Runtime.Identity -is [Collections.IDictionary]){$idOK=[bool]$raw.Runtime.Identity[[string]$p.Pid]}elseif($raw.Runtime.Identity){$idOK=[bool]$raw.Runtime.Identity.([string]$p.Pid)}
  if(!$idOK){continue}
  $connections=@($raw.Runtime.Connections|Where-Object {$_.Pid -eq $p.Pid -and $_.IdentityMatched -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')})
  $dns=@();foreach($e in $raw.Runtime.NetworkObservation.DNSEvents|Where-Object {$_ -and $_.Id -in @(3006,3008)}){$di=Resolve-IRDNSIdentity $e $raw.Runtime.NetworkObservation;if($di.IdentityMatched -and [string]$di.Pid -eq [string]$p.Pid -and $di.StartUtc -eq $p.StartUtc){$dns+=$e}}
  $mem=@($raw.Memory|Where-Object {$_.Pid -eq $p.Pid -and $_.IdentityMatched -and $_.Hits.Count})
  $imageChecks=@($raw.ImageIntegrity|Where-Object {$_.Pid -eq $p.Pid -and $_.IdentityMatched -and $_.Check.Complete -and $_.Check.Suspicious})
  $modules=@($raw.Modules|Where-Object Pid -eq $p.Pid);$bad=@();$why=@();$proof=@();$exe=$map[$p.Path]
  foreach($m in $modules){
   $f=$map[[string]$m.Path];if(!$f -or !$f.Exists){continue}
   $mismatch=$f.Signature -eq 'HashMismatch'
   $concealed=$f.HiddenParent -and $f.Signature -in @('NotSigned','NotTrusted')
   $directPersistence=@($refs|Where-Object {$_.Path -eq $m.Path -and $_.Kind -notin @('Detection','ServiceEvent')})
   $unsignedSystemExtension=$p.Path -match '(?i)\\Windows\\(System32|SysWOW64)\\(svchost|lsass|winlogon|services|spoolsv|vssvc|ipconfig)\.exe$' -and $f.Signature -in @('NotSigned','NotTrusted') -and $directPersistence.Count -and ($connections.Count -or $dns.Count)
   if($mismatch -or $concealed -or $unsignedSystemExtension){$bad+=$m.Path;$why+=('已加载模块 '+$m.Path+'；签名='+$f.Signature+'；隐藏父目录='+$f.HiddenParent);$proof+=('模块快照 PID='+$p.Pid+' 已加载 '+$m.Path+'；不由安装包或同目录关系推断')}
  }
  $role=if($exe.OriginalFilename){[IO.Path]::GetFileName([string]$exe.OriginalFilename)}else{$p.Name}
  # Version metadata is attacker controlled; a vendor claim is not a trust decision.
  # Require a verified current instance and an actually loaded adjacent untrusted DLL.
  $vendorModules=@($modules|Where-Object {
   $mf=$map[[string]$_.Path]
   $_.Path -and $mf.Exists -and $_.Path -ne $p.Path -and $_.IdentityMatched -eq $true -and $_.StartUtc -eq $p.StartUtc -and
   (Split-Path $_.Path) -eq (Split-Path $p.Path) -and $mf.Signature -in @('NotSigned','HashMismatch')
  })
  if($exe.Exists -and $exe.Signature -in @('NotSigned','HashMismatch') -and
     $exe.CompanyName -match '^(?i)Microsoft Corporation$' -and $exe.OriginalFilename -match '(?i)\.exe$' -and
     $role -ne [IO.Path]::GetFileName($p.Path) -and $p.Path -match '(?i)\\(Users|ProgramData|Temp)\\' -and $vendorModules.Count){
   $why+=('运行映像未通过签名验证却宣称Microsoft厂商，原始文件名与当前名称不同，并实际加载同目录未签名/摘要损坏DLL；版本信息不是信任依据。')
   $bad+=@($p.Path)+@($vendorModules.Path)
   $proof+=('映像签名='+$exe.Signature+'；CompanyName='+$exe.CompanyName+'；OriginalFilename='+$role+'；磁盘路径='+$p.Path)
   foreach($vm in $vendorModules){$proof+=('已核对同一实例加载 '+$vm.Path+'；PID='+$p.Pid+'；启动UTC='+$p.StartUtc+'；模块签名='+$map[$vm.Path].Signature)}
  }
  if(($connections.Count -or $dns.Count) -and $role -match '^(?i)(ipconfig|whoami|hostname|conhost|vssvc)\.exe$'){$why+=('工具角色 '+$role+' 出现网络连接/连接尝试或DNS查询，检查其内存及加载模块；正常磁盘签名不能排除被利用')}
  if($mem.Count){$why+='同一进程实例存在非映像可执行PE或线程起点异常；需区分注入与合法动态代码'}
  if($imageChecks.Count){$why+='同一进程主映像的可执行节与磁盘显著不同；已排除基址重定位和IAT字节，仍需区分空洞/篡改、正常热补丁与解包';foreach($check in $imageChecks){$proof+=('主映像节 '+$check.Check.Section+' 比较='+$check.Check.Compared+'字节；差异='+$check.Check.Changed+'字节；掩码='+$check.Check.Masked+'字节；磁盘样例='+$check.Check.DiskSample+'；内存样例='+$check.Check.MemorySample)}}
  $direct=@($refs|Where-Object {$_.Path -eq $p.Path -and $_.Kind -notin @('Detection','ServiceEvent')})
  if(($connections.Count -or $dns.Count) -and $direct.Count -and $exe.Signature -in @('NotSigned','HashMismatch','NotTrusted')){$why+='网络连接/连接尝试或DNS查询 + 驻留配置 + 当前映像签名未通过';$bad+=$p.Path}
  if(!$why.Count){continue}
  $bad=@($bad|Select-Object -Unique);$target=if($bad.Count){$bad[0]}else{$p.Path}
  $linkPaths=@($bad);if(!(IR-SharedHost $p.Path)){$linkPaths+=$p.Path}
  $related=@($refs|Where-Object {$_.Path -in $linkPaths})
  $persist=@($raw.Persistence|Where-Object {$s=$_;@($related|Where-Object {$_.Kind -eq $s.Kind -and $_.Location -eq $s.Location -and $_.Name -eq $s.Name}).Count})
  $serviceNames=@($persist|Where-Object Kind -eq 'ServiceDll'|ForEach-Object {$_.ServiceName}|Where-Object {$_})
  $persist+=@($raw.Persistence|Where-Object {$_.Kind -eq 'Service' -and $_.Name -in $serviceNames})
  $guids=@();foreach($e in $raw.Events|Where-Object {$_.Log -match 'Sysmon' -and $_.Id -eq 1 -and $_.Data.Image -eq $p.Path -and [string]$_.Data.ProcessId -eq [string]$p.Pid}){try{if([math]::Abs(([datetime]::SpecifyKind([datetime]$e.Data.UtcTime,[DateTimeKind]::Utc)-([datetime]$p.StartUtc).ToUniversalTime()).TotalSeconds) -le 3){$guids+=$e.Data.ProcessGuid}}catch{}}
  $proof+=('进程身份核对：PID='+$p.Pid+'；启动UTC='+$p.StartUtc+'；映像='+$p.Path)
  $objects=@($bad|Where-Object {!(IR-SharedHost $_)}|ForEach-Object {@{Type='File';Location=$_;Name='';Extra=('SHA256='+$map[$_].SHA256);Decision='已实际加载/运行的异常候选，保全并确认恶意性；不自动处置'}})
  $rank=if($bad.Count -and $persist.Count){100}elseif($bad.Count){90}elseif($imageChecks.Count){70}else{30}
  $filePaths=@($bad)+@($p.Path)|Select-Object -Unique
  $result.Add([pscustomobject]@{Id='';Kind=if($bad.Count){'运行中载荷追查'}else{'内存执行区域待核查'};EvidenceRank=$rank;RuntimeCase=$true;AutoInvestigation=$true;ContextOnly=$false;Target=$target;Severity='中';Verdict='运行证据明确；恶意性仍需核实';State=('PID '+$p.Pid+'，路径和启动时间复核一致');Trigger=$why;Proof=$proof;EvidenceIds=@();Processes=@($p);ProcessGuids=$guids;Files=@($filePaths|ForEach-Object {$map[$_]});LoadedModules=$modules;MemoryEvidence=@($mem)+@($imageChecks);Persistence=$persist;Connections=$connections;HistoryEvents=@();ManualObjects=$objects;Verification=@();MissingEvidence=@();Containment='优先保全本进程的内存、列出的已加载文件及精确启动配置；确认恶意后人工处置，不因宿主被利用而删除系统文件。';ExitCriteria='复查该载荷、引用配置、相关进程及外联是否再次出现。'})
 }
 # Live parent and child instances can be linked by the OS parent field, provided both creation times and identities are verified. This does not alone prove injection.
 foreach($c in $result|Where-Object {$_.EvidenceRank -ge 90 -and $_.LoadedModules.Path -contains $_.Target}){
  $parent=$c.Processes[0]
  foreach($child in $raw.Processes|Where-Object {$_.ParentPid -eq $parent.Pid -and $_.Path -and $_.StartUtc}){
   $ok=$false;if($raw.Runtime.Identity -is [Collections.IDictionary]){$ok=[bool]$raw.Runtime.Identity[[string]$child.Pid]}elseif($raw.Runtime.Identity){$ok=[bool]$raw.Runtime.Identity.([string]$child.Pid)}
   try{if(!$ok -or [datetimeoffset]$parent.StartUtc -gt [datetimeoffset]$child.StartUtc){continue}}catch{continue}
   $dnsOwned=@(foreach($e in $raw.Runtime.NetworkObservation.DNSEvents){$di=Resolve-IRDNSIdentity $e $raw.Runtime.NetworkObservation;if($di.IdentityMatched -and [string]$di.Pid -eq [string]$child.Pid -and [datetimeoffset]$di.StartUtc -eq [datetimeoffset]$child.StartUtc){$e}})
   $conn=@($raw.Runtime.Connections|Where-Object {$_.Pid -eq $child.Pid -and $_.IdentityMatched})
   if(!$dnsOwned.Count -and !$conn.Count){continue}
   $c.Processes+=@($child);$c.Connections+=@($conn);$c.Proof+=('OS ParentProcessId='+$child.ParentPid+'：宿主 '+$parent.Path+'（启动UTC='+$parent.StartUtc+'）→ 子进程 '+$child.Path+'（PID='+$child.Pid+'；启动UTC='+$child.StartUtc+'）；两个当前实例均已复核。父子关系本身不证明注入。')
   $c.Trigger+=('关联子进程有同实例DNS/连接证据；通信归属按子进程启动时间复核，不从安装包猜测。');$c.EvidenceRank=110
  }
 }
 # A exited injected host is still discoverable from behavior logs, without an installer or live PID.
 foreach($e in $raw.Events|Where-Object {$_.Log -match 'Sysmon' -and $_.Id -in @(8,25)}){
  $d=$e.Data;$guid=if($e.Id -eq 8){[string]$d.TargetProcessGUID}else{[string]$d.ProcessGuid};if(!$guid){continue}
  $net=@($raw.Events|Where-Object {$_.Log -match 'Sysmon' -and $_.Id -in @(3,22) -and $_.Data.ProcessGuid -eq $guid})
  if(!$net.Count -or @($result|Where-Object {$guid -in $_.ProcessGuids}).Count){continue}
  $target=if($e.Id -eq 8){$d.TargetImage}else{$d.Image}
  $result.Add([pscustomobject]@{Id='';Kind='历史宿主异常与通信';RuntimeCase=$true;AutoInvestigation=$true;ContextOnly=$false;Target=$target;Severity='中';Verdict='异常行为与通信属于同一历史实例，尚未认定恶意';State='历史进程实例；不套用当前同名进程';Trigger=@('远程线程/进程篡改事件与DNS/连接事件共享ProcessGuid');Proof=@($e.Log+'#'+$e.RecordId+'；GUID='+$guid+'；源映像='+$d.SourceImage);EvidenceIds=@();Processes=@();ProcessGuids=@($guid);Files=@();LoadedModules=@();MemoryEvidence=@();Persistence=@();Connections=@();HistoryEvents=@($e)+$net;ManualObjects=@();Verification=@();MissingEvidence=@('日志不一定记录了原始投放者和载荷文件；没有证据不指定系统宿主为清理对象');Containment='按此GUID的模块加载、文件和注册表写入继续追查；本卡不指认当前同名进程。';ExitCriteria='核对关联载荷与配置及后续异常通信。'})
 }
 return $result.ToArray()
}
