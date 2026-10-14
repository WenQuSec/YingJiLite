# Generic evidence pivots. Never executes inspected files, scripts or DLLs.
function IR-NormalPath([string]$s,[string]$systemRoot='C:\Windows') {
 if(!$s){return ''};$s=$s.Trim().Trim('"');$s=$s -replace '^\\\?\?\\','' -replace '^\\SystemRoot', $systemRoot
 if($s -match '^[a-zA-Z]:\\' -and $s -notmatch '[\r\n]'){return $s};return ''
}
function IR-References($raw) {
 foreach($s in $raw.Persistence){
  $paths=@($s.Path)
  foreach($m in [regex]::Matches([string]$s.Command,'(?i)"(?<p>[a-z]:\\[^"\r\n]+\.(?:exe|dll|sys|ps1|vbs|js|hta|bat|cmd|scr))"|(?<p>[a-z]:\\[^\s",;]+\.(?:exe|dll|sys|ps1|vbs|js|hta|bat|cmd|scr))(?=$|[\s",;])')){$paths+=$m.Groups['p'].Value}
  foreach($p in @($paths|Where-Object {$_}|Select-Object -Unique)){
   $p=IR-NormalPath $p; if(!$p){continue}
   [pscustomobject]@{Path=$p;Kind=$s.Kind;Location=$s.Location;Name=$s.Name;Command=$s.Command;Enabled=$s.Enabled;HostPath=$s.Path}
  }
 }
 foreach($d in $raw.Detections){foreach($resource in $d.Resources){
  # Defender can describe a file, process or a nested container. Only actual paths become pivots.
  foreach($m in [regex]::Matches([string]$resource,'(?i)(?:^|[;\s])(?:file|containerfile|process):_?(?<p>[a-z]:\\[^;\r\n]+)')){
   $p=IR-NormalPath $m.Groups['p'].Value;if($p){[pscustomobject]@{Path=$p;Kind='Detection';Location=('Defender ThreatID='+$d.ThreatID);Name=[string]$d.ThreatID;Command=[string]$resource;Enabled=$null;HostPath=''}}
  }
 }}
 foreach($e in $raw.Events){
  if(($e.Log -eq 'System' -and $e.Id -eq 7045) -or ($e.Log -eq 'Security' -and $e.Id -eq 4697)){
   $cmd=if($e.Data.ImagePath){[string]$e.Data.ImagePath}else{[string]$e.Data.ServiceFileName}
   $p=PathOf $cmd;if($p){[pscustomobject]@{Path=$p;Kind='ServiceEvent';Location=($e.Log+'#'+$e.RecordId+' UTC='+$e.TimeUtc);Name=$e.Data.ServiceName;Command=$cmd;Enabled=$null;HostPath=''}}
  }
 }
}
function IR-PEImports([string]$path) {
 $f=$null;$r=$null
 try {
  $f=[IO.File]::Open($path,'Open','Read','ReadWrite');$r=New-Object IO.BinaryReader($f)
  if($f.Length -lt 256){throw 'Not a PE'}
  if($r.ReadUInt16() -ne 0x5a4d){throw 'Not a PE'};$f.Position=60;$pe=$r.ReadUInt32()
  if($pe -gt $f.Length-256){throw 'Invalid PE offset'};$f.Position=$pe
  if($r.ReadUInt32() -ne 0x4550){throw 'Invalid PE signature'}
  $f.Position=$pe+6;$count=$r.ReadUInt16();if($count -gt 96){throw 'Section limit'}
  $f.Position=$pe+20;$optional=$r.ReadUInt16();$f.Position=$pe+24;$magic=$r.ReadUInt16()
  $dd=if($magic -eq 0x10b){96}elseif($magic -eq 0x20b){112}else{throw 'Unsupported PE'}
  if($optional -lt $dd+16){throw 'Missing import directory'}
  $f.Position=$pe+24+$dd+8;$import=$r.ReadUInt32();$size=$r.ReadUInt32()
  if(!$import -or !$size){return [pscustomobject]@{Names=@();Status='Parsed';Detail='No static imports'}}
  $sections=@();for($i=0;$i -lt $count;$i++){
   $at=$pe+24+$optional+40*$i;if($at+40 -gt $f.Length){throw 'Truncated sections'}
   $f.Position=$at+8;$vs=$r.ReadUInt32();$va=$r.ReadUInt32();$rs=$r.ReadUInt32();$rp=$r.ReadUInt32()
   $sections+=@{VA=[long]$va;Size=[long]$rs;Raw=[long]$rp}
  }
  $offset={param([long]$rva) foreach($s in $sections){if($rva -ge $s.VA -and $rva -lt $s.VA+$s.Size){return ($s.Raw+$rva-$s.VA)}};return -1}
  $table=& $offset $import;if($table -lt 0){throw 'Unmapped import directory'}
  $names=@();$limit=[math]::Min(512,[math]::Floor($size/20))
  for($i=0;$i -lt $limit;$i++){
   $at=$table+20*$i;if($at+20 -gt $f.Length){throw 'Truncated imports'}
   $f.Position=$at;$a=$r.ReadUInt32();$b=$r.ReadUInt32();$c=$r.ReadUInt32();$nameRva=$r.ReadUInt32();$e=$r.ReadUInt32()
   if(!($a -bor $b -bor $c -bor $nameRva -bor $e)){break}
   $at=& $offset $nameRva;if($at -lt 0 -or $at -ge $f.Length){continue};$f.Position=$at
   $name='';for($j=0;$j -lt 260 -and $f.Position -lt $f.Length;$j++){$ch=$r.ReadByte();if(!$ch){break};$name+=[char]$ch}
   if($name -match '^[\w.\-]+\.dll$'){$names+=$name}
  }
  return [pscustomobject]@{Names=@($names|Select-Object -Unique);Status='Parsed';Detail='Static imports only; resolution and execution not proven'}
 }catch{return [pscustomobject]@{Names=@();Status='Unavailable';Detail=$_.Exception.Message}}
 finally{if($r){$r.Dispose()}elseif($f){$f.Dispose()}}
}
function IR-HiddenParent([string]$path) {
 $p=Split-Path $path;for($i=0;$i -lt 4 -and $p;$i++){
  # AppData and ProgramData are hidden by Windows itself; that is not a concealment signal.
  if((Split-Path $p -Leaf) -in @('AppData','Roaming','Local','LocalLow','ProgramData')){return ''}
  if($p -eq ($env:ProgramFiles+'\WindowsApps')){return ''}
  if($p.TrimEnd('\') -eq [IO.Path]::GetPathRoot($p).TrimEnd('\')){return ''}
  try{$item=Get-Item -LiteralPath $p -Force -ErrorAction Stop;if($item.Attributes -band [IO.FileAttributes]::Hidden){return $p}}catch{return ''}
  $p=Split-Path $p
 };return ''
}
function Get-GeneralEvidence($raw) {
 $refs=@(IR-References $raw);$neighbors=New-Object 'Collections.Generic.List[object]';$scripts=New-Object 'Collections.Generic.List[object]'
 $known=@('ntdll.dll','kernel32.dll','kernelbase.dll');$knownStatus='Read'
 try{$key=Get-Item -LiteralPath 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -ErrorAction Stop;foreach($name in $key.GetValueNames()){$v=[string]$key.GetValue($name);if($v -match '(?i)^[\w.\-]+\.dll$'){$known+=$v}}}catch{$knownStatus='Unavailable';Gap 'KnownDLLs' $_.Exception.Message}
 $seen=@{};$clock=[Diagnostics.Stopwatch]::StartNew();$hostCount=0;$neighborCount=0;$scriptCount=0
 # Persistence and historical alert paths are collected before optional module hashing exhausts the budget.
 $priorityRefs=@($refs|Where-Object {$_.Kind -eq 'Detection' -or $_.Path -notmatch '(?i)\\Windows\\'}|Sort-Object @{e={if($_.Kind -eq 'Detection'){0}elseif($_.Path -match '(?i)\\(Users|ProgramData|Temp)\\'){1}else{2}}}|ForEach-Object {$_.Path})
 $networkPids=@($raw.NetworkObservation.Connections.Pid);foreach($e in $raw.NetworkObservation.DNSEvents|Where-Object {$_}){$di=Resolve-IRDNSIdentity $e $raw.NetworkObservation;if($di.IdentityMatched){$networkPids+=[int]$di.Pid}}
 $priorityProcesses=@($raw.Processes|Where-Object {$_.Path -and ($_.Pid -in $networkPids -or $_.Path -notmatch '(?i)\\Windows\\')}|Sort-Object @{e={if($_.Pid -in $networkPids){0}else{1}}}|ForEach-Object {$_.Path})
 $paths=$priorityRefs+$priorityProcesses+@($refs.Path)+@($raw.Processes|Where-Object Path|ForEach-Object {$_.Path})
 $anomalyDirs=@($cache.Values|Where-Object {$_.Signature -eq 'HashMismatch'}|ForEach-Object {Split-Path $_.Path}|Select-Object -Unique)
 $diskTargets=@($raw.Investigation.DeepFiles|Where-Object {$_.HiddenDirectory -or $_.DisguisedPE -or $_.ContentAnomaly -or (Split-Path $_.Path) -in $anomalyDirs}|ForEach-Object {$_.Path})
 $paths=$diskTargets+$priorityRefs+$priorityProcesses+@($refs.Path)+@($raw.Processes|Where-Object Path|ForEach-Object {$_.Path})
 $paths=@($paths|Select-Object -Unique)
 foreach($p in $paths){
  if($clock.Elapsed.TotalSeconds -gt 35){Gap '自动追查预算' '35秒预算已到；后续目标未检查';break}
  # Live module validation includes Windows images; no directory trust bypass.
  $m=Meta $p;if(!$m -or !$m.Exists){continue}
  if($p -match '(?i)\.(ps1|vbs|js|hta|bat|cmd)$' -and $m.Size -le 128KB -and $scriptCount -lt 120){
   $scriptCount++;try{$content=[IO.File]::ReadAllText($p);$scripts.Add([pscustomobject]@{Path=$p;Text=$content;Status='Read'})}catch{Gap ('脚本读取 '+$p) $_.Exception.Message}
  }
  if($p -notmatch '(?i)\.exe$' -or $hostCount -ge 120){continue}
  $hostCount++;$dir=Split-Path $p;$imports=IR-PEImports $p
  if($imports.Status -ne 'Parsed'){Gap ('PE导入表 '+$p) $imports.Detail}
  try{
   if(!$seen.ContainsKey($dir)){$seen[$dir]=@(Get-ChildItem -LiteralPath $dir -File -Force -Filter '*.dll' -ErrorAction Stop)}
   $dlls=@($seen[$dir])
   if($dir -match '(?i)\\Windows\\(System32|SysWOW64)(\\|$)'){$dlls=@($dlls|Where-Object {$_.Name -in $imports.Names})}
  }catch{Gap ('相邻DLL '+$dir) $_.Exception.Message;continue}
  if($dlls.Count -gt 64){Gap ('相邻DLL '+$dir) '超过64个DLL；优先静态导入项，剩余截断'}
  foreach($dll in $dlls|Sort-Object @{e={if($_.Name -in $imports.Names){0}else{1}}}|Select-Object -First 64){
   if($clock.Elapsed.TotalSeconds -gt 35){break}
   if($neighborCount -ge 400){break};$neighborCount++;$dm=Meta $dll.FullName
   $neighbors.Add([pscustomobject]@{HostPath=$p;Path=$dll.FullName;Imported=($dll.Name -in $imports.Names);ImportStatus=$imports.Status;KnownSystemImport=($dll.Name -in $known -or $dll.Name -match '^(?i)(api|ext)-ms-win-');HiddenDirectory=(IR-HiddenParent $dll.FullName)})
  }
 }
 Gap '自动追查范围' ('以启动配置、杀软路径和服务安装事件自动选取目标；检查 '+$hostCount+' 个EXE邻域、'+$neighborCount+' 个DLL、'+$scriptCount+' 个脚本。上限120/400/120、35秒；未解析延迟/动态导入和完整浏览器数据库。')
 $pivots=@();foreach($n in $neighbors){
  $direct=@($refs|Where-Object {$_.Path -eq $n.HostPath -and $_.Kind -notin @('Detection','ServiceEvent') -and $_.Enabled -ne $false})
  $h=$cache[$n.HostPath];$dll=$cache[$n.Path]
  if($direct.Count -and $n.HostPath -match '(?i)\\(Users|ProgramData|Temp)\\' -and $h.Signature -eq 'Valid' -and !$n.KnownSystemImport -and $dll.Signature -in @('NotSigned','NotTrusted','HashMismatch')){
   $pivots+=@{HostPath=$n.HostPath;Path=$n.Path;Imported=$n.Imported;Signature=$dll.Signature;SHA256=$dll.SHA256;HiddenDirectory=$n.HiddenDirectory;References=$direct;Assessment=if($n.Imported){'驻留配置引用签名宿主，静态导入引用同目录未验证DLL；目录不隐藏也保留。未判定恶意，未证明执行。'}else{'驻留配置引用签名宿主；同目录未验证DLL作为追查候选，不证明被宿主加载。'}}
  }
 }
 return [pscustomobject]@{References=$refs;Neighbors=$neighbors.ToArray();Scripts=$scripts.ToArray();KnownDLLNames=$known;KnownDLLStatus=$knownStatus;PersistencePivots=$pivots}
}
function Get-GeneralCases($raw,$files) {
 $result=New-Object 'Collections.Generic.List[object]';$map=@{};foreach($f in $files){$map[[string]$f.Path]=$f}
 $refs=@(IR-References $raw);$general=$raw.General
 function AddCase($kind,$target,$reason,$severity,$hostPath,$source,$pidOnly=0) {
  if(!$target){return};$key=$kind+'|'+$target+'|'+$pidOnly
  if($mapCases.ContainsKey($key)){return};$mapCases[$key]=$true
  $related=@($refs|Where-Object {$_.Path -eq $target -or ($hostPath -and $_.Path -eq $hostPath)})
  $persist=@($raw.Persistence|Where-Object {$s=$_;@($related|Where-Object {$_.Kind -eq $s.Kind -and $_.Location -eq $s.Location -and $_.Name -eq $s.Name}).Count})
  $pids=@($raw.Modules|Where-Object Path -eq $target|ForEach-Object {$_.Pid})
  $processes=@($raw.Processes|Where-Object {if($pidOnly){$_.Pid -eq $pidOnly}else{($_.Path -eq $target -and !(IR-SharedHost $target)) -or $_.Pid -in $pids -or ($hostPath -and $_.Path -eq $hostPath -and !(IR-SharedHost $hostPath))}})
  $paths=@($target);if($hostPath){$paths+=$hostPath}
  $objects=@();if($map[$target] -and $map[$target].Exists -and !(IR-SharedHost $target) -and $kind -ne '系统工具异常外联'){$objects+=@{Type='File';Location=$target;Name='';Extra=('SHA256='+$map[$target].SHA256);Decision='已定位的可疑文件；保全后核实恶意性，由人工决定处置。'}}
  foreach($s in $persist){$objects+=@{Type=$s.Kind;Location=$s.Location;Name=$s.Name;Extra=$s.Command;Decision='配置引用关系已确定；只处置经确认恶意的精确对象。'}}
  $history=@($raw.Events|Where-Object {($_.Log -eq 'System' -and $_.Id -eq 7045 -and $_.Data.ServiceName -in $persist.Name) -or ($_.Log -match 'Sysmon' -and ($_.Data.Image -in $paths -or $_.Data.TargetFilename -eq $target -or $_.Data.ImageLoaded -eq $target))}|Sort-Object TimeUtc|Select-Object -First 30)
  $proof=@($source);foreach($s in $persist){$proof+=($s.Kind+' '+$s.Location+' ['+$s.Name+'] → '+$s.Command)}
  if($hostPath){$proof+=('磁盘宿主 '+$hostPath+' 的静态导入表引用同目录DLL '+$target+'；尚不证明执行或启动配置存在')}
  foreach($p in $processes){$proof+=('当前 PID '+$p.Pid+' | '+$p.Path+' | 启动 '+$p.StartUtc)}
  $missing=@();if(!$persist.Count){$missing+='未找到直接关联的驻留配置'};if(!$history.Count){$missing+='没有关联历史事件，入口和投放者未知'}
  $result.Add([pscustomobject]@{Id='';Kind=$kind;Target=$target;EvidenceRank=$(if($kind -match '编码|签名'){80}elseif($persist.Count){75}else{50});Severity=$severity;ContextOnly=$false;Verdict='异常依据已列出；恶意性待确认';State=if($processes.Count){'有关联运行实例'}else{'配置或磁盘证据；未确认正在运行'};Trigger=@($reason);EvidenceIds=@();AutoInvestigation=$true;Proof=$proof;Processes=$processes;Files=@($paths|ForEach-Object {if($map[$_]){$map[$_]}});Persistence=$persist;Connections=@($raw.TCP|Where-Object {$_.Pid -in $processes.Pid -and $_.State -eq 'Established'});HistoryEvents=$history;ManualObjects=$objects;Verification=@();MissingEvidence=$missing;Containment='按本卡片精确对象核查和保全；确认恶意后人工隔离、处置。';ExitCriteria='人工处置后复扫，逐项核对相关启动配置、文件与运行实例；历史告警不会因处置成功自动消失。'})
 }
 $mapCases=@{}
 foreach($r in $refs|Where-Object Kind -eq 'Detection'){
  $m=$map[$r.Path];$active=@($refs|Where-Object {$_.Path -eq $r.Path -and $_.Kind -notin @('Detection','ServiceEvent')})
  if(($m -and $m.Exists) -or $active.Count){
   AddCase '历史告警路径仍存在' $r.Path '杀软曾报告此路径；当前文件仍存在或配置仍引用它。历史处置成功不能替代现状检查，文件可能已被合法替换。' '中' '' $r.Location
   foreach($c in $result|Where-Object {$_.Target -eq $r.Path -and $_.Kind -eq '历史告警路径仍存在'}){$c.ContextOnly=(!$c.Processes.Count -and !$c.Persistence.Count);if($c.ContextOnly){$c.ManualObjects=@()}}
  }
 }
 foreach($n in $general.Neighbors){
  $m=$map[$n.Path];$h=$map[$n.HostPath]
  if(!$m -or !$h -or !$n.Imported -or $n.KnownSystemImport -or $h.Signature -ne 'Valid'){continue}
  $untrusted=$m.Signature -in @('NotSigned','HashMismatch','NotTrusted')
  if($untrusted -and ($n.HiddenDirectory -or $m.Signature -eq 'HashMismatch')){
   $severity=if($m.Signature -eq 'HashMismatch'){'高'}else{'中'}
   AddCase '磁盘宿主异常DLL组合' $n.Path ('有效签名EXE静态导入同目录未验证DLL；DLL签名='+$m.Signature+'；隐藏目录='+$n.HiddenDirectory+'。这是结构组合线索；驻留配置和运行证据分别核对。') $severity $n.HostPath 'PE静态导入 + 文件属性/签名'
  }
 }
 foreach($r in $refs|Where-Object {$_.Kind -notin @('Detection','ServiceEvent')}){
  $m=$map[$r.Path];if(!$m -or !$m.Exists){continue}
  if($m.Signature -eq 'HashMismatch'){AddCase '驻留目标签名损坏' $r.Path '启动配置直接引用的文件签名摘要不符。文件需保全复核。' '高' '' ($r.Kind+' '+$r.Location)}
  if($r.Enabled -ne $false -and $r.Kind -in @('ServiceDll','LSA','AppCertDlls','AppInit','Winlogon Notify','Print monitor','Netsh helper') -and $r.Path -match '(?i)\\Windows\\' -and $m.Signature -in @('NotSigned','NotTrusted')){AddCase '系统目录中的未验证驻留模块' $r.Path ('系统扩展启动配置直接引用该DLL，但文件签名未通过；系统目录和厂商文字不作为放行依据。签名='+$m.Signature+'；这是待核实异常，不直接判定恶意。') '中' '' ($r.Kind+' '+$r.Location)}
  if($r.Kind -eq 'Driver' -and $r.Path -notmatch '(?i)\\Windows\\' -and $m.Signature -in @('NotSigned','HashMismatch','NotTrusted')){
   $install=@($refs|Where-Object {$_.Kind -eq 'ServiceEvent' -and $_.Path -eq $r.Path})
   if($install.Count -or $m.HiddenParent){AddCase '异常驱动配置' $r.Path '非Windows目录的驱动签名未通过，且存在安装事件或隐藏目录；配置存在不等于已经加载，按需启动不等于开机自启。' '高' '' ($install.Location -join ';')}
  }
 }
 foreach($r in $refs|Where-Object {$_.Kind -notin @('Detection','ServiceEvent')}){
  $m=$map[$r.Path];if(!$m -or !$m.Exists){continue}
  if($m.Signature -in @('NotSigned','NotTrusted') -and $m.HiddenParent){AddCase '隐藏目录中的驻留目标' $r.Path ('驻留配置引用隐藏子目录中的未验证签名文件；隐藏目录='+$m.HiddenParent+'；签名='+$m.Signature+'。按配置的启用及启动类型判读，不直接认定恶意。') '中' '' ($r.Kind+' '+$r.Location)}
 }
 foreach($f in $raw.Investigation.DeepFiles){
  $m=$map[$f.Path];if(!$m -or !$m.Exists){continue}
  if($f.ContentShape.Kind -eq 'EncodedPE'){AddCase '编码隐藏的落地载荷候选' $f.Path ($f.ContentShape.Detail+'；由近期或隐藏目录文件内容自动发现，不依赖安装器或已知名称；尚未证明运行和C2。') '中' '' '深度文件枚举 + 解码头部独立PE校验'}
  elseif($f.ContentShape.Kind -eq 'DisguisedZipWithCode'){AddCase '伪装图片或文本的程序容器' $f.Path ($f.ContentShape.Detail+'；仅枚举目录，没有解压或执行；尚未证明被调用。') '中' '' '深度文件枚举 + ZIP目录'}
  elseif($f.DisguisedPE -and $f.HiddenDirectory){AddCase '隐藏目录内的伪装PE文件' $f.Path ('非程序扩展名但存在有效PE结构，位于隐藏子目录 '+$f.HiddenDirectory+'；不能仅凭伪装确定恶意性。') '中' '' '深度文件枚举 + PE结构检查'}
  elseif($m.Signature -eq 'HashMismatch'){AddCase '落地文件签名摘要不符' $f.Path '深度目录检查发现签名摘要与文件内容不符；关联路径和创建时间已保留。' '高' '' '深度文件枚举 + Authenticode'}
 }
 foreach($module in $raw.Modules){
  if(!$module.Path -or !$module.ProcessPath){continue};$m=$map[$module.Path];$h=$map[$module.ProcessPath]
  if($module.ProcessPath -match '(?i)\\Windows\\(System32|SysWOW64)\\(svchost|lsass|winlogon|services|spoolsv|vssvc|ipconfig)\.exe$' -and $module.Path -ne $module.ProcessPath -and $m.Signature -in @('NotSigned','HashMismatch','NotTrusted')){
   AddCase '系统宿主加载未验证模块' $module.Path ('系统宿主实际加载签名未通过的DLL；宿主='+$module.ProcessPath+'；PID='+$module.Pid+'；需区分合法扩展与注入，位于系统目录也保留该线索。') '中' '' ('加载模块快照 PID='+$module.Pid) $module.Pid
  }
 }
 foreach($s in $general.Scripts){
  if($s.Status -ne 'Read'){continue};$t=[string]$s.Text
  if(IR-ScriptExecutionSignal $t $s.Path){
   AddCase '驻留脚本下载执行组合' $s.Path '启动配置引用的脚本内容包含下载与执行组合或挖矿协议。已只读检查内容；合法运维也可能符合。' '中' '' '启动引用 + 脚本静态内容'
  }
 }
 foreach($p in $raw.Processes){
  if(!$p.Path){continue}
  $connections=@($raw.TCP|Where-Object {$_.Pid -eq $p.Pid -and $_.State -eq 'Established' -and (IR-PublicAddress $_.RemoteAddress)})
  if(!$connections.Count){continue};$m=$map[$p.Path]
  $role=if($m.OriginalFilename){[IO.Path]::GetFileName([string]$m.OriginalFilename)}else{$p.Name}
  if($role -match '^(?i)(ipconfig|whoami|hostname|conhost|vssvc)\.exe$'){
   AddCase '系统工具异常外联' $p.Path ('该工具角色出现公网TCP会话，需优先排查注入、加载内容与启动来源；磁盘签名正常不排除内存被利用，连接本身不证明C2。角色='+$role) '中' '' ('TCP快照 PID='+$p.Pid) $p.Pid
  }
 }
 return $result.ToArray()
}
function IR-ScriptExecutionSignal([string]$text,[string]$path) {
 if($path -and $path -notmatch '(?i)\.ps1$'){
  return ($text -match '(?i)(DownloadString|DownloadFile|XMLHTTP|WinHttpRequest|https?://)' -and $text -match '(?i)(\.Run\s*\(|\.Exec\s*\(|rundll32|regsvr32|mshta)')
 }
 $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
 $commands=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst]},$true))
 $exec=@($commands|Where-Object {$_.GetCommandName() -in @('IEX','Invoke-Expression','Start-Process','rundll32','rundll32.exe','regsvr32','mshta')}).Count
 if($exec -and $text -match '(?i)(DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|https?://)'){return $true}
 foreach($cmd in $commands){if($cmd.Extent.Text -match '(?i)(?:^|\s)(--url|-o)\s+[''"\s]*stratum\+(tcp|ssl)://'){return $true}}
 return $false
}
function IR-SharedHost([string]$p){return [IO.Path]::GetFileName($p) -match '^(?i)(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|svchost|dllhost|ipconfig|whoami|hostname|conhost|vssvc)\.exe$'}
function IR-PublicAddress([string]$s){
 $ip=$null;if(![Net.IPAddress]::TryParse($s,[ref]$ip)){return $false};if([Net.IPAddress]::IsLoopback($ip)){return $false}
 if($ip.IsIPv4MappedToIPv6){return IR-PublicAddress ($ip.MapToIPv4().ToString())}
 $b=$ip.GetAddressBytes();if($b.Length -eq 4){return !($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))}
 return !($ip.IsIPv6LinkLocal -or $ip.IsIPv6Multicast -or $ip.Equals([Net.IPAddress]::IPv6Any) -or ($b[0] -band 0xfe) -eq 0xfc)
}
