# Independent network acquisition: evidence must not depend on a malware-rule hit.
function Convert-IRNetworkEvent($event) {
 $xml=[xml]$event.ToXml();$data=@{}
 foreach($v in $xml.Event.EventData.Data){if($v.Name){$data[[string]$v.Name]=[string]$v.'#text'}}
 [pscustomobject]@{Log=[string]$event.ProviderName;Id=$event.Id;RecordId=$event.RecordId;TimeUtc=$event.TimeCreated.ToUniversalTime().ToString('o');EmitterPid=[string]$xml.Event.System.Execution.ProcessID;Data=$data}
}
function Get-IRNetworkObservation([string]$directory,[int]$seconds=20) {
 $session='YingJiDNS-'+[guid]::NewGuid().ToString('N');$etl=Join-Path $directory ($session+'.etl')
 $socketSession=$session+'-socket';$socketEtl=Join-Path $directory ($socketSession+'.etl')
 $notes=New-Object 'Collections.Generic.List[string]';$rows=New-Object 'Collections.Generic.List[object]';$samples=New-Object 'Collections.Generic.List[object]'
 $dnsEvents=@();$socketEvents=@();$active=$false;$socketActive=$false;$traceStatus='未启动';$started=[datetime]::UtcNow
 $instances=@{};$lastProcesses=-10
 function Capture-IRProcessInstances {
  $time=[datetime]::UtcNow.ToString('o')
  try{foreach($p in Get-CimInstance Win32_Process -ErrorAction Stop){
   if(!$p.CreationDate){continue};$start=$p.CreationDate.ToUniversalTime().ToString('o');$key=[string]$p.ProcessId+'|'+$start
   if($instances.ContainsKey($key)){$instances[$key].LastSeenUtc=$time}else{$instances[$key]=[pscustomobject]@{Pid=[int]$p.ProcessId;StartUtc=$start;Path=[string]$p.ExecutablePath;Name=[string]$p.Name;Command=[string]$p.CommandLine;ParentPid=[int]$p.ParentProcessId;FirstSeenUtc=$time;LastSeenUtc=$time}}
  }}catch{$notes.Add('观察期进程快照失败：'+$_.Exception.Message)}
 }
 Capture-IRProcessInstances
 try {
  $message=@(& "$env:SystemRoot\System32\logman.exe" start $session -ets -p Microsoft-Windows-DNS-Client "0xffffffffffffffff" 5 -o $etl -f bincirc -max 16 2>&1)
  $active=$LASTEXITCODE -eq 0
  if($active){$traceStatus='已启动'}else{$notes.Add('DNS ETW启动失败：'+($message -join ' '));$traceStatus='启动失败'}
  $socketMessage=@(& "$env:SystemRoot\System32\logman.exe" start $socketSession -ets -p Microsoft-Windows-Winsock-AFD "0xffffffffffffffff" 5 -o $socketEtl -f bincirc -max 16 2>&1);$socketActive=$LASTEXITCODE -eq 0
  if(!$socketActive){$notes.Add('套接字ETW启动失败：'+($socketMessage -join ' '))}
  $timer=[Diagnostics.Stopwatch]::StartNew()
  do {
   if($timer.Elapsed.TotalSeconds-$lastProcesses -ge 2){Capture-IRProcessInstances;$lastProcesses=$timer.Elapsed.TotalSeconds}
   $time=[datetime]::UtcNow.ToString('o')
   try{
    $tcp=@(Get-NetTCPConnection -ErrorAction Stop|Where-Object {$_.State -notin @('Listen','Bound') -and $_.RemoteAddress -notin @('0.0.0.0','::')})
    foreach($n in $tcp){$rows.Add([pscustomobject]@{Pid=[int]$n.OwningProcess;LocalAddress=$n.LocalAddress;LocalPort=$n.LocalPort;RemoteAddress=$n.RemoteAddress;RemotePort=$n.RemotePort;State=[string]$n.State;TimeUtc=$time;IdentityMatched=$false})}
    $samples.Add(@{TimeUtc=$time;Count=$tcp.Count;Status='Read'})
   }catch{$samples.Add(@{TimeUtc=$time;Count=0;Status='Failed'});$notes.Add($_.Exception.Message)}
   if($timer.Elapsed.TotalSeconds -lt $seconds){Start-Sleep -Milliseconds 500}
  }while($timer.Elapsed.TotalSeconds -lt $seconds)
 }finally{
  if($active){
   $stop=@(& "$env:SystemRoot\System32\logman.exe" stop $session -ets 2>&1)
   if($LASTEXITCODE -eq 0){$traceStatus='完成'}else{$traceStatus='停止失败';$notes.Add('仅本工具创建的ETW会话未能停止：'+$session+'；'+($stop -join ' '))}
  }
  if($socketActive){$stop=@(& "$env:SystemRoot\System32\logman.exe" stop $socketSession -ets 2>&1);if($LASTEXITCODE -ne 0){$notes.Add('本工具套接字会话停止未成功：'+$socketSession+'；'+($stop -join ' '))}}
  Capture-IRProcessInstances
 }
 # A session may have ended before our stop call. Its existing ETL still contains evidence.
 $parsed=0
 foreach($trace in @(@{Path=$etl;Active=$active},@{Path=$socketEtl;Active=$socketActive})){
 if($trace.Active -and [IO.File]::Exists($trace.Path)){
  try{
   $query="*[System[(Provider[@Name='Microsoft-Windows-DNS-Client'] and (EventID=3006 or EventID=3008)) or (Provider[@Name='Microsoft-Windows-Winsock-AFD'] and (EventID=1 or EventID=4 or EventID=5 or EventID=6 or EventID=21 or EventID=22 or EventID=1000 or EventID=1007 or EventID=1013 or EventID=1017 or EventID=1018))]]"
   $events=@(Get-WinEvent -Path $trace.Path -FilterXPath $query -Oldest -MaxEvents 50000 -ErrorAction Stop)
   if($events.Count -ge 50000){$notes.Add('相关ETW达到50000事件解析上限；循环ETL保留，仍可能缺失更早的事件')}
   $dnsEvents+=@($events|Where-Object ProviderName -eq 'Microsoft-Windows-DNS-Client'|ForEach-Object {Convert-IRNetworkEvent $_})
   $socketEvents+=@($events|Where-Object ProviderName -eq 'Microsoft-Windows-Winsock-AFD'|ForEach-Object {Convert-IRNetworkEvent $_});$parsed++
  }catch{if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){$traceStatus='解析失败';$notes.Add($_.Exception.Message)}}
 }
 }
 if($traceStatus -eq '停止失败' -and $parsed){$traceStatus='已解析提前结束的会话；观察窗口可能不完整'}
 foreach($n in $rows){$owners=@($instances.Values|Where-Object {$_.Pid -eq $n.Pid -and $_.Path -and $_.StartUtc -le $n.TimeUtc -and $_.LastSeenUtc -ge $n.TimeUtc});if($owners.Count -eq 1){$n|Add-Member ProcessPath $owners[0].Path;$n|Add-Member ProcessStartUtc $owners[0].StartUtc;$n|Add-Member ObservationIdentityMatched $true}}
 $observation=[pscustomobject]@{StartUtc=$started.ToString('o');EndUtc=[datetime]::UtcNow.ToString('o');RequestedSeconds=$seconds;TraceStatus=$traceStatus;TraceFile=$etl;TraceFiles=@($etl,$socketEtl);Session=$session;Sessions=@($session,$socketSession);DNSEvents=$dnsEvents;SocketEvents=$socketEvents;ProcessInstances=@($instances.Values);Connections=$rows.ToArray();Samples=$samples.ToArray();Notes=$notes.ToArray();Limit='DNS与套接字分别使用16MiB循环ETL，互不挤占。只观察本次窗口，不能恢复过去通信；DoH/自带解析器、短命进程、循环日志覆盖及50000相关事件解析上限仍可能漏报。UDP端点不含远端，套接字事件只覆盖实际收到的操作；进程每2秒快照。'}
 $observation|Add-Member SocketConnections @(Resolve-IRSocketEvidence $observation)
 $observation.DNSEvents=@(Compress-IRQueryEvidence $dnsEvents $observation)
 return $observation
}
function Resolve-IRDNSIdentity($e,$observation) {
 $d=$e.Data;$owner=[string]$d.ClientPID;$basis='DNS ClientPID字段'
 if(!$owner){$owner=[string]$d.ProcessId;$basis='DNS ProcessId字段'}
 # 3006/3008 are the API caller's query start/completion. Other events can be emitted by Dnscache.
 if(!$owner -and $e.Id -in @(3006,3008)){$owner=[string]$e.EmitterPid;$basis='DNS查询开始/完成事件的调用进程PID'}
 if(!$owner){return [pscustomobject]@{Pid=$e.EmitterPid;Path='';StartUtc='';IdentityMatched=$false;Basis='只有事件发出PID，未确认查询调用者'}}
 if(![object]::ReferenceEquals($script:irIndexedInstances,$observation.ProcessInstances)){
  $script:irIndexedInstances=$observation.ProcessInstances;$script:irInstanceIndex=@{}
  foreach($p in $observation.ProcessInstances|Where-Object {$_}){$key=[string]$p.Pid;if(!$script:irInstanceIndex.ContainsKey($key)){$script:irInstanceIndex[$key]=New-Object 'Collections.Generic.List[object]'};$script:irInstanceIndex[$key].Add($p)}
 }
 $matches=@();try{$time=[datetimeoffset]$e.TimeUtc;foreach($p in $script:irInstanceIndex[$owner]){if($p.Path -and [datetimeoffset]$p.StartUtc -le $time -and [datetimeoffset]$p.LastSeenUtc -ge $time){$matches+=@($p)}}}catch{}
 if($matches.Count -eq 1){return [pscustomobject]@{Pid=$owner;Path=$matches[0].Path;StartUtc=$matches[0].StartUtc;IdentityMatched=$true;Basis=($basis+'；创建时间早于事件，事件后仍观测到同一实例')}}
 [pscustomobject]@{Pid=$owner;Path='';StartUtc='';IdentityMatched=$false;Basis=($basis+'；未取得覆盖查询时间的进程身份，不套用当前同PID进程')}
}
function Compress-IRQueryEvidence($events,$observation) {
 $grouped=@{};$rows=New-Object 'Collections.Generic.List[object]'
 foreach($e in $events|Where-Object {$_ -and $_.Id -in @(3006,3008) -and $_.Data.QueryName}){
  $identity=Resolve-IRDNSIdentity $e $observation
  # Include the verified process creation time in the key; never merge PID reuse.
  $key=@([string]$identity.Pid,[string]$identity.StartUtc,$e.Id,$e.Data.QueryName,$e.Data.QueryType,$e.Data.QueryStatus,$e.Data.QueryResults)|ConvertTo-Json -Compress
  if(!$identity.IdentityMatched){$key+='|record='+$e.RecordId}
  if($grouped.ContainsKey($key)){$old=$grouped[$key];$old.Count++;$old.LastUtc=$e.TimeUtc;$old.LastRecordId=$e.RecordId}
  else{$row=$e.PSObject.Copy();$row|Add-Member Count 1 -Force;$row|Add-Member FirstUtc $e.TimeUtc -Force;$row|Add-Member LastUtc $e.TimeUtc -Force;$row|Add-Member LastRecordId $e.RecordId -Force;$grouped[$key]=$row;$rows.Add($row)}
 }
 return $rows.ToArray()
}
function Convert-IRSocketAddress($d) {
 try{
  if($d.AddressLen -and $d.Address -match '^[0-9A-Fa-f]+$' -and ([string]$d.Address).Length -ge 16){
   $hex=[string]$d.Address;$bytes=New-Object byte[] ($hex.Length/2);for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[Convert]::ToByte($hex.Substring($i*2,2),16)}
   $family=[BitConverter]::ToUInt16($bytes,0);$port=[int]$bytes[2]*256+[int]$bytes[3]
   if($family -eq 2 -and $bytes.Length -ge 16){$ip=New-Object Net.IPAddress -ArgumentList (,[byte[]]$bytes[4..7])}elseif($family -eq 23 -and $bytes.Length -ge 28){$ip=New-Object Net.IPAddress -ArgumentList (,[byte[]]$bytes[8..23])}else{return $null}
  }else{
   $ip=$null;if(![Net.IPAddress]::TryParse([string]$d.Address,[ref]$ip)){$number=if([string]$d.Address -match '^0x'){[Convert]::ToUInt32(([string]$d.Address).Substring(2),16)}else{[uint32]$d.Address};$ip=New-Object Net.IPAddress -ArgumentList (,[BitConverter]::GetBytes($number))}
   # Legacy AFD template encodes Port as a network-order UInt16.
   $rawPort=[int]$d.Port;$port=(($rawPort -band 255)*256)+(($rawPort -shr 8) -band 255)
  }
  return [pscustomobject]@{Address=$ip.ToString();Port=$port}
 }catch{return $null}
}
function Resolve-IRSocketEvidence($observation) {
 $sockets=@{};$result=New-Object 'Collections.Generic.List[object]'
 foreach($e in $observation.SocketEvents|Sort-Object TimeUtc,RecordId){
  $d=$e.Data;$key=[string]$d.Process+'|'+[string]$d.Endpoint
  if($e.Id -eq 1 -or ($e.Id -eq 1000 -and $d.EnterExit -eq '0')){
   $number=if($d.ProcessId){[string]$d.ProcessId}else{[string]$d.UserModePid}
   try{$owner=if($number -match '^0x'){[Convert]::ToInt32($number.Substring(2),16)}else{[int]$number};$sockets[$key]=@{Pid=$owner;Last=$null}}catch{};continue
  }
  if($e.Id -in @(6,1017) -or ($e.Id -eq 1018 -and $d.EnterExit -eq '1')){
   $entry=$sockets[$key];if($entry -and $entry.Last){$status=if($d.Error){[string]$d.Error}else{[string]$d.Status};$entry.Last.Status=$status;$entry.Last.EvidenceRecords+=@($e.RecordId)
    try{$code=if($status -match '^0x'){[Convert]::ToUInt32($status.Substring(2),16)}else{[uint32]$status};if($code -eq 0){$entry.Last.State='SocketConnectCompleted'}elseif($code -ge 0x80000000L){$entry.Last.State='SocketConnectFailed'}}catch{}
   };continue
  }
  if($e.Id -notin @(4,5,21,22,1007,1013,1018)){continue}
  if($e.Id -ge 1000 -and $d.EnterExit -ne '0'){continue}
  $endpoint=Convert-IRSocketAddress $d;if(!$endpoint){continue}
  $entry=$sockets[$key];$owner=if($entry){$entry.Pid}else{[int]$e.EmitterPid}
  $identity=Resolve-IRDNSIdentity @{Id=0;TimeUtc=$e.TimeUtc;Data=@{ProcessId=$owner}} $observation
  $row=[pscustomobject]@{Pid=$owner;RemoteAddress=$endpoint.Address;RemotePort=$endpoint.Port;State=if($e.Id -in @(21,22,1007,1013)){'SocketSendTo'}else{'SocketConnectAttempt'};Status='未取得完成状态';TimeUtc=$e.TimeUtc;Source='AFD ETW';IdentityMatched=$false;ObservationIdentityMatched=$identity.IdentityMatched;ProcessPath=$identity.Path;ProcessStartUtc=$identity.StartUtc;EvidenceRecords=@($e.RecordId)}
  $result.Add($row);if(!$entry){$entry=@{Pid=$owner;Last=$null};$sockets[$key]=$entry};$entry.Last=$row
 }
 $result.ToArray()
}
function Get-IRIndependentNetwork($raw) {
 $rows=New-Object 'Collections.Generic.List[object]'
 $tcpRows=@($raw.Runtime.Connections)+@($raw.TCP|Where-Object {$_ -and $_.RemoteAddress -and $_.State -notin @('Listen','Bound')}|ForEach-Object {[pscustomobject]@{Pid=$_.Pid;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=$_.State;TimeUtc=$raw.Host.TimeUtc;IdentityMatched=$false}})
 foreach($n in $tcpRows|Where-Object {$_ -and $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0','::','127.0.0.1','::1')}){
  $p=@($raw.Processes|Where-Object Pid -eq $n.Pid|Select-Object -First 1)
  $path=if($n.ObservationIdentityMatched){$n.ProcessPath}elseif($n.IdentityMatched -and $p.Count){$p[0].Path}else{''}
  $start=if($n.ProcessStartUtc){$n.ProcessStartUtc}elseif($n.IdentityMatched -and $p.Count){$p[0].StartUtc}else{''}
  $label=switch([string]$n.State){'SocketConnectAttempt'{'套接字连接尝试'}'SocketConnectFailed'{'套接字连接失败'}'SocketConnectCompleted'{'套接字连接完成'}'SocketSendTo'{'套接字定向发送'}'SynSent'{'TCP连接尝试'}'Established'{'TCP已建立'}default{'TCP '+$n.State}}
  $rows.Add([pscustomobject]@{Kind=$label;Value=($n.RemoteAddress+':'+$n.RemotePort);TimeUtc=$n.TimeUtc;Pid=$n.Pid;Process=$path;ProcessStartUtc=$start;Identity=if($path){'PID及启动时间已复核'}else{'仅采样PID；未确认进程实例'};Source=if($n.Source){$n.Source}else{'TCP观察'};Detail=('远端不自动认定为C2；操作状态='+$n.Status)})
 }
 # Events carry their own historical identity, never join them to a live process by PID alone.
 $events=@($raw.Events|Where-Object {($_.Log -match 'Sysmon' -and $_.Id -in @(3,22)) -or ($_.Log -eq 'Security' -and $_.Id -in @(5156,5157,5152,5153)) -or $_.Log -match 'DNS-Client'})+@($raw.Runtime.NetworkObservation.DNSEvents)
 foreach($e in $events|Where-Object {$_}){
  $d=$e.Data;$value='';$proc='';$owner='';$identity='';$detail='';$kind='';$start=''
  if($e.Log -match 'DNS-Client'){
   $value=[string]$d.QueryName;if(!$value){$value=[string]$d.Name};if(!$value){continue}
   $peers=@($events|Where-Object {$_.Log -match 'DNS-Client' -and $_.Data.QueryName -eq $value -and $_.Id -in @(3006,3008)})
   if($e.Id -notin @(3006,3008) -and $peers.Count){continue}
   $resolved=Resolve-IRDNSIdentity $e $raw.Runtime.NetworkObservation;$owner=$resolved.Pid;$proc=$resolved.Path;$identity=$resolved.Basis;$start=$resolved.StartUtc
   if($e.Id -eq 3006 -and @($peers|Where-Object {$_.Id -eq 3008 -and $_.EmitterPid -eq $e.EmitterPid -and $_.Data.QueryType -eq $d.QueryType -and $_.TimeUtc -ge $e.TimeUtc}).Count){continue}
   $kind=if($e.Id -eq 3008 -and $d.QueryStatus -ne '0'){'DNS查询失败'}elseif($e.Id -eq 3008){'DNS查询完成'}elseif($e.Id -eq 3006){'DNS查询开始'}else{'DNS查询事件'}
   $detail='类型='+$d.QueryType+'；状态='+$d.QueryStatus+'；结果='+$d.QueryResults+'；解析返回地址不等于已连接，DNS服务器地址不当作C2'
  }elseif($e.Log -match 'Sysmon'){
   $proc=$d.Image;$owner=$d.ProcessId;$identity='ProcessGuid='+$d.ProcessGuid
   if($e.Id -eq 22){$value=$d.QueryName;$kind='进程DNS';$detail='状态='+$d.QueryStatus+'；结果='+$d.QueryResults}else{$value=$d.DestinationIp+':'+$d.DestinationPort;$kind='Sysmon连接';$detail='协议='+$d.Protocol+'；主动='+$d.Initiated}
  }else{
   $value=$d.DestAddress+':'+$d.DestPort;$proc=$d.Application;$owner=$d.ProcessID;$identity='历史事件路径/PID；不对应当前进程实例';$kind=if($e.Id -eq 5156){'WFP允许'}else{'WFP阻止'};$detail='方向='+$d.Direction+'；协议='+$d.Protocol+'；允许不等于连接成功'
  }
  if($value){$rows.Add([pscustomobject]@{Kind=$kind;Value=$value;TimeUtc=$e.TimeUtc;Pid=$owner;Process=$proc;ProcessStartUtc=$start;Identity=$identity;Source=($e.Log+' EventID='+$e.Id);EvidenceRecords=@($e.RecordId);Detail=$detail})}
 }
 foreach($d in $raw.DNS){if($d.Entry){$rows.Add([pscustomobject]@{Kind='DNS缓存';Value=([string]$d.Entry+' → '+[string]$d.Data);TimeUtc=$raw.Host.TimeUtc;Pid='';Process='';Identity='无进程归属，时间为读取时间';Source='DNS缓存';Detail=('类型='+$d.Type+'；TTL='+$d.TimeToLive+'；缓存不是查询历史')})}}
 # Collapse repeated observations, retaining first/last timestamps and count.
 $map=@{};$output=New-Object 'Collections.Generic.List[object]'
 foreach($r in $rows){$key=@($r.Kind,$r.Value,[string]$r.Pid,$r.Process,$r.ProcessStartUtc,$r.Identity,$r.Source,$r.Detail)|ConvertTo-Json -Compress
  if($map.ContainsKey($key)){$old=$map[$key];$old.Count++;if($r.EvidenceRecords){$old.EvidenceRecords+=@($r.EvidenceRecords)};if($r.TimeUtc -lt $old.FirstUtc){$old.FirstUtc=$r.TimeUtc};if($r.TimeUtc -gt $old.LastUtc){$old.LastUtc=$r.TimeUtc}}else{
   $r|Add-Member FirstUtc $r.TimeUtc;$r|Add-Member LastUtc $r.TimeUtc;$r|Add-Member Count 1;$map[$key]=$r;$output.Add($r)
  }
 }
 [pscustomobject]@{Observation=$raw.Runtime.NetworkObservation|Select-Object StartUtc,EndUtc,RequestedSeconds,TraceStatus,TraceFile,Notes,Limit;Rows=$output.ToArray();Assessment='独立网络证据，不依赖异常规则命中。条目未判定为恶意，不能直接称为C2。空结果不证明未尝试通信。'}
}
function Get-IRNetworkPivots($raw,$network) {
 $all=New-Object 'Collections.Generic.List[object]';$seen=@{};$index=0
 $refs=@(IR-References $raw);$metadata=@{};foreach($f in $raw.Files){if($f.Path){$metadata[[string]$f.Path]=$f}}
 foreach($n in $network.Rows|Where-Object {$_.Process -and $_.ProcessStartUtc}){
  $key=[string]$n.Pid+'|'+$n.ProcessStartUtc+'|'+$n.Process;if($seen.ContainsKey($key)){continue};$seen[$key]=$true
  $current=@($raw.Processes|Where-Object {[string]$_.Pid -eq [string]$n.Pid -and $_.Path -eq $n.Process -and $_.StartUtc -eq $n.ProcessStartUtc})
  $entries=@($network.Rows|Where-Object {[string]$_.Pid -eq [string]$n.Pid -and $_.Process -eq $n.Process -and $_.ProcessStartUtc -eq $n.ProcessStartUtc})
  $loaded=@();$alerts=@();$memory=@();$configs=@();$services=@()
  if($current.Count -eq 1){
   $loaded=@($raw.Modules|Where-Object {[string]$_.Pid -eq [string]$n.Pid})
   foreach($m in $loaded){$f=$metadata[[string]$m.Path];if($f -and ($f.Signature -eq 'HashMismatch' -or ($f.Signature -in @('NotSigned','NotTrusted') -and ($f.HiddenParent -or $m.Path -notmatch '(?i)\\Windows\\')))){$alerts+=@{Path=$m.Path;Signature=$f.Signature;SHA256=$f.SHA256;HiddenParent=$f.HiddenParent}}}
   $memory=@($raw.Memory|Where-Object {[string]$_.Pid -eq [string]$n.Pid -and $_.StartUtc -eq $n.ProcessStartUtc -and $_.IdentityMatched -and $_.Hits.Count})
   $linked=@($loaded.Path);if(!(IR-SharedHost $n.Process)){$linked+=$n.Process}
   $reference=@($refs|Where-Object {$_.Path -in $linked -and $_.Kind -notin @('Detection','ServiceEvent')})
   $configs=@($raw.Persistence|Where-Object {$s=$_;@($reference|Where-Object {$_.Kind -eq $s.Kind -and $_.Location -eq $s.Location -and $_.Name -eq $s.Name}).Count})
   $services=@($raw.Persistence|Where-Object {$_.Kind -eq 'Service' -and [string]$_.Pid -eq [string]$n.Pid})
  }
  $index++;$all.Add([pscustomobject]@{Id=('N{0:d3}' -f $index);Pid=$n.Pid;Path=$n.Process;StartUtc=$n.ProcessStartUtc;CurrentIdentityMatched=($current.Count -eq 1);Command=if($current.Count){$current[0].Command}else{''};Network=$entries;LoadedModuleCount=$loaded.Count;ModuleCandidates=$alerts;MemoryEvidence=$memory;ConfigurationReferences=$configs;HostedServices=$services;Assessment='按观察期进程身份追查。网络条目及配置引用不自动认定恶意；没有当前同一实例时，不套用当前进程的模块或服务。'})
 }
 $all.ToArray()
}
