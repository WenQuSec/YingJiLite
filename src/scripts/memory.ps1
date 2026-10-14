# Independent implementation using documented Windows read APIs; no writes or dumps.
function Initialize-MemoryReader {
 if('YingJiMemory.Reader' -as [type]){return}
 throw '内嵌原生探测类型未加载'
}
function Get-IRLoadedModules($Processes){
 Initialize-MemoryReader
 foreach($p in $Processes){
  if(!$p.Path -or $p.Pid -eq $PID -or $p.Path -eq $IRLauncher){continue}
  $scan=[YingJiMemory.Reader]::Modules([int]$p.Pid)
  $identity=$false;try{$now=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Pid);$identity=($now -and $now.ExecutablePath -eq $p.Path -and $now.CreationDate.ToUniversalTime().ToString('o') -eq $p.StartUtc)}catch{}
  if(!$identity){Gap ('模块身份 PID '+$p.Pid) '当前路径/启动时间未与采集目标复核一致；不归属模块';continue}
  if(!$scan.Complete){Gap ('模块快照 PID '+$p.Pid) ('Toolhelp模块快照不完整；Win32Error='+$scan.Error+'；已取得='+$scan.Modules.Count)}
  foreach($m in $scan.Modules){[pscustomobject]@{Pid=$p.Pid;ProcessPath=$p.Path;StartUtc=$p.StartUtc;Path=$m.Path;Address=$m.Address;Size=$m.Size;IdentityMatched=$true;Source='Toolhelp32 SNAPMODULE+SNAPMODULE32'}}
 }
}
function Get-MemoryEvidence($Processes,$NetworkPids=@()){
 Initialize-MemoryReader
 $timer=[Diagnostics.Stopwatch]::StartNew();$count=0
 foreach($p in $Processes|Sort-Object @{e={if($_.Pid -in $NetworkPids){0}elseif($_.Path -match '(?i)\\Windows\\'){2}else{1}}},Pid){
  if($p.Pid -le 4 -or $p.Pid -eq $PID -or $p.Path -eq $IRLauncher){continue}
  if($timer.Elapsed.TotalSeconds -ge 45){Gap '内存预算' '达到45秒上限，未扫描完所有进程';break}
  $r=[YingJiMemory.Reader]::Inspect([int]$p.Pid,700);$count++
  $identity=$false
  try{$current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Pid);$identity=($current -and $current.ExecutablePath -eq $p.Path -and $current.CreationDate.ToUniversalTime().ToString('o') -eq $p.StartUtc)}catch{}
  [pscustomobject]@{Pid=$p.Pid;Path=$p.Path;StartUtc=$p.StartUtc;IdentityMatched=[bool]$identity;Opened=$r.Opened;Complete=$r.Complete;Error=$r.Error;Regions=$r.Regions;ReadFailures=$r.ReadFailures;ThreadFailures=$r.ThreadFailures;BytesRead=$r.BytesRead;Hits=@($r.Hits)}
 }
 Gap '内存检查范围' ('已检查'+$count+'个进程；只读非映像映射的PE头与线程起始地址，不保存内存转储；不覆盖无头shellcode、内核隐藏或所有进程空洞，合法动态代码也可能命中。')
}
function Initialize-IRImageVerifier {
 if('YingJiImage.Reader' -as [type]){return}
 throw '内嵌原生探测类型未加载'
}
function Get-IRImageIntegrity($Processes,$Modules) {
 Initialize-IRImageVerifier;$timer=[Diagnostics.Stopwatch]::StartNew()
 foreach($p in $Processes){
  if(!$p.Path -or $p.Pid -le 4 -or $p.Pid -eq $PID -or $p.Path -eq $IRLauncher){continue}
  if($timer.Elapsed.TotalSeconds -gt 30){Gap '主映像内存比较预算' '30秒已到，未完成对象仍为未知';break}
  $module=@($Modules|Where-Object {$_.Pid -eq $p.Pid -and $_.Path -eq $p.Path -and $_.IdentityMatched}|Select-Object -First 1);if(!$module.Count){continue}
  $check=[YingJiImage.Reader]::InspectCode([int]$p.Pid,$p.Path,[long]$module[0].Address)
  $valid=$false;try{$now=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Pid);$valid=($now -and $now.ExecutablePath -eq $p.Path -and $now.CreationDate.ToUniversalTime().ToString('o') -eq $p.StartUtc)}catch{}
  [pscustomobject]@{Pid=$p.Pid;Path=$p.Path;StartUtc=$p.StartUtc;IdentityMatched=$valid;Check=$check}
 }
}
