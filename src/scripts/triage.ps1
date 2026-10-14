param([object]$RawEvidence,[object]$Analysis,[string]$Output,[switch]$Live)
$ErrorActionPreference='Stop'
$raw=$RawEvidence;$a=$Analysis
$cases=New-Object 'Collections.Generic.List[object]';$diagnostics=New-Object 'Collections.Generic.List[object]'
function Q($s){return "'"+([string]$s).Replace("'","''")+"'"}
function ContainsPath($text,$path){if(!$path){return $false};return [regex]::IsMatch([string]$text,'(?i)(?<![\w\\.\-])'+[regex]::Escape([string]$path)+'(?=$|[\s"'',;])')}
function SharedHost($path){return [IO.Path]::GetFileName([string]$path) -match '^(powershell|pwsh|cmd|rundll32|regsvr32|mshta|wscript|cscript|svchost|dllhost)\.exe$'}
function PersistCommand($s){
 if($s.Kind -eq 'Task'){$at=([string]$s.Location).LastIndexOf('\');$folder=$s.Location.Substring(0,$at+1);$name=$s.Location.Substring($at+1);$get='Get-ScheduledTask -TaskPath '+(Q $folder)+' -TaskName '+(Q $name);return $get+' | Format-List TaskPath,TaskName,State,Actions,Principal,Triggers'+[Environment]::NewLine+$get+' | Get-ScheduledTaskInfo | Format-List LastRunTime,LastTaskResult'}
 if($s.Kind -in @('Service','Driver')){return 'Get-CimInstance '+$(if($s.Kind -eq 'Driver'){'Win32_SystemDriver'}else{'Win32_Service'})+' | Where-Object Name -eq '+(Q $s.Name)+' | Format-List *'}
 if($s.Kind -eq 'Startup'){return 'Get-Item -LiteralPath '+(Q $s.Location)+' | Format-List FullName,Length,CreationTimeUtc,LastWriteTimeUtc'}
 $key=([string]$s.Location) -replace '^HKLM\\','Registry::HKEY_LOCAL_MACHINE\' -replace '^HKCU\\','Registry::HKEY_CURRENT_USER\'
 return 'Get-ItemProperty -LiteralPath '+(Q $key)+' -Name '+(Q $s.Name)+' | Format-List *'
}
foreach($f in $a.Findings|Where-Object Title -eq '启动目标不存在或不可读'){
 $s=@($raw.Persistence|Where-Object Path -eq $f.Target|Select-Object -First 1)
 $note='目标文件无法读取；没有据此确认恶意配置。';$next='按软件运维问题核查归属，不能据此进行安全清理。'
 if($s.Count -and $s[0].LastResult -eq '2147942402'){$note='任务最近运行返回0x80070002（找不到文件），目标无法读取。该项应归为失效启动配置，不作为木马发现。'}
 $diagnostics.Add([pscustomobject]@{Title='失效启动配置';Location=$f.Source;Target=$f.Target;Fact=$note;Next=$next;Command=if($s.Count){PersistCommand $s[0]}else{''}})
}
$def=@($raw.Defender|Where-Object {$null -ne $_.RealTimeProtectionEnabled}|Select-Object -First 1)
$audit=@($a.Findings|Where-Object Title -eq '审计/防护变化事件')
foreach($f in $audit){
 $current=if($f.Source -notmatch 'Windows Defender'){'存在审计日志变化记录；这条记录本身不能识别操作者或证明攻击'}elseif($def.Count -and $def[0].RealTimeProtectionEnabled){'采集时实时防护已开启；历史记录只说明当时曾关闭'}else{'采集时实时防护关闭或未成功读取'}
 $diagnostics.Add([pscustomobject]@{Title='历史防护/审计状态';Location=$f.Source;Target='';Fact=$current+'；单个历史事件不证明有人实施攻击。';Next='若关闭时间与异常首次出现一致，查对应窗口的4688/4104/EDR记录；否则不计入攻击链。';Command='Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,IsTamperProtected'})
}
$candidates=@($a.Findings|Where-Object {$_.Title -notin @('账户/任务/服务变更记录','Defender历史检测（可能已处置）','服务路径未加引号','启动目标不存在或不可读','审计/防护变化事件')})
$accepted=@()
foreach($f in $candidates){
 if($f.Source -match '^(Installer|History|Memory): '){continue}
 if($f.Target -eq $raw.Host.CollectorPath -and $f.Title -eq '用户可写位置的未验证签名进程'){continue}
 if($f.Title -eq '用户可写位置的未验证签名进程'){
  $p=@($raw.Processes|Where-Object Path -eq $f.Target);$persistence=@($raw.Persistence|Where-Object {$_.Path -eq $f.Target -and $_.Enabled})
  $connection=@($raw.TCP|Where-Object {$_.Pid -in $p.Pid -and $_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0$)'})
  if(!$persistence.Count -and !$connection.Count){continue}
 }
 $accepted+=$f
}
foreach($group in $accepted|Group-Object {if($_.Target -and !(SharedHost $_.Target)){[string]$_.Target}elseif($_.Source -match '(?i)PID[= ](\d+)'){[string]$_.Target+'|PID='+$matches[1]}else{[string]$_.Target+'|'+[string]$_.Source}}){
 $fs=@($group.Group);$f=$fs[0];$target=[string]$f.Target
 $pids=@();foreach($ff in $fs){if($ff.Source -match '(?i)PID[= ](\d+)'){$pids+=[int]$matches[1]}}
 $ip='';$parsedIp=$null;if($target -and [Net.IPAddress]::TryParse($target,[ref]$parsedIp)){$ip=$target}
 if($ip){$pids+=@($raw.TCP|Where-Object RemoteAddress -eq $ip|ForEach-Object {$_.Pid})}
 $modules=@($raw.Modules|Where-Object {$_.Path -eq $target})
 $pids+=@($modules|ForEach-Object {$_.Pid})
 $paths=@(@($target)+@($modules|ForEach-Object {$_.ProcessPath})|Where-Object {$_})
 if($pids.Count){$processes=@($raw.Processes|Where-Object Pid -in $pids)}else{$processes=@($raw.Processes|Where-Object {$_.Path -and $_.Path -in $paths})}
 $paths+=@($processes|Where-Object Path|ForEach-Object {$_.Path})
 $pids=@($processes|ForEach-Object {$_.Pid})
 $persist=@($raw.Persistence|Where-Object {
  $s=$_
  $direct=($s.Kind+': '+$s.Location+' 值/名称='+$s.Name) -in $fs.Source -or $s.Location -in $fs.Source
  if($direct){return $true}
  # A shared interpreter path does not identify the script, service or task it runs.
  if($target -and !(SharedHost $target) -and (ContainsPath $s.Command $target)){return $true}
  if($s.Path -in $paths -and !(SharedHost $s.Path)){return $true}
  return $false
 })
 # Configuration findings against a shared host must not select every host instance.
 if(!$pids.Count -and (SharedHost $target)){$processes=@()}
 if((SharedHost $target) -and !@($fs|Where-Object {$_.Source -match '(?i)PID[= ]\d+'}).Count){$processes=@();$pids=@()}
 $connections=@($raw.TCP|Where-Object {$_.Pid -in $pids -and $_.State -eq 'Established'})
 $files=@($a.Files|Where-Object Path -in $paths)
 $prows=New-Object 'Collections.Generic.List[object]'
 foreach($p in $processes){
  $owner=if($p.Owner){[string]$p.Owner}else{'未知：未读取进程属主'};$ownerEvidence='离线字段或未提供'
  if($Live -and $prows.Count -lt 20){try{$current=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.Pid);if($current -and $current.ExecutablePath -eq $p.Path -and $current.CreationDate.ToUniversalTime().ToString('o') -eq $p.StartUtc){$o=Invoke-CimMethod -InputObject $current -MethodName GetOwner;if($o.ReturnValue -eq 0){$owner=$o.Domain+'\'+$o.User;$ownerEvidence='GetOwner返回0；启动时间/路径与快照一致'}}else{$ownerEvidence='进程已结束或PID快照发生变化'}}catch{$ownerEvidence=$_.Exception.Message}}
  $parent=@($raw.Processes|Where-Object Pid -eq $p.ParentPid|Select-Object -First 1)
  $parentText='未知/已结束';if($parent.Count -and $parent[0].StartUtc -and $p.StartUtc -and [datetime]$parent[0].StartUtc -le [datetime]$p.StartUtc){$parentText='PID '+$parent[0].Pid+' '+$parent[0].Path+'（PPID候选，不证明攻击因果）'}
  $prows.Add([pscustomobject]@{Pid=$p.Pid;Path=$p.Path;Command=$p.Command;StartUtc=$p.StartUtc;Owner=$owner;OwnerEvidence=$ownerEvidence;Parent=$parentText})
 }
 $triggerEvents=@($raw.Events|Where-Object {($_.Log+'#'+$_.RecordId+' UTC='+$_.TimeUtc) -in $fs.Source})
 $relatedEvents=@($raw.Events|Where-Object {$target -and !(SharedHost $target) -and (($_.Data.Image -eq $target) -or ($_.Data.TargetFilename -eq $target) -or ($_.Data.ImageLoaded -eq $target))}|Sort-Object TimeUtc|Select-Object -First 10)
 $eventRows=@(@($triggerEvents)+@($relatedEvents)|Sort-Object Log,RecordId -Unique|Sort-Object TimeUtc)
 $evidenceIds=@($fs|ForEach-Object {$_.Id})
 $verify=New-Object 'Collections.Generic.List[object]'
 if($target -match '^[a-zA-Z]:\\'){
  $verify.Add([pscustomobject]@{Question='文件是否仍存在、内容是否改变';Command=('Get-Item -LiteralPath '+(Q $target)+' | Format-List FullName,Length,CreationTimeUtc,LastWriteTimeUtc' + [Environment]::NewLine+'Get-FileHash -LiteralPath '+(Q $target)+' -Algorithm SHA256');Expected='对照本报告SHA256；内容不一致时不能沿用旧样本结论。'})
  $verify.Add([pscustomobject]@{Question='签名与下载来源';Command=('Get-AuthenticodeSignature -LiteralPath '+(Q $target)+' | Format-List Status,SignerCertificate'+[Environment]::NewLine+'Get-Content -LiteralPath '+(Q $target)+' -Stream Zone.Identifier -ErrorAction SilentlyContinue');Expected='合法签名不能排除被侧加载；Zone.Identifier可能缺失，缺失不证明本地生成。'})
 }
 foreach($p in $processes|Select-Object -First 4){$safePid=0;if(![int]::TryParse([string]$p.Pid,[ref]$safePid) -or $safePid -le 0){continue};$verify.Add([pscustomobject]@{Question=('PID '+$safePid+'当前身份和外联');Command=('Get-CimInstance Win32_Process -Filter "ProcessId='+$safePid+'" | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate'+[Environment]::NewLine+'Get-NetTCPConnection -OwningProcess '+$safePid+' | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State');Expected='先核对启动时间和路径，防止PID重用；仅把同一实例的连接计入链路。'})}
 foreach($s in $persist|Select-Object -First 6){$verify.Add([pscustomobject]@{Question=('持久化是否仍启用：'+$s.Kind+' '+$s.Name);Command=(PersistCommand $s);Expected='确认名称、完整位置、命令、启用状态与运行账号；不能只因位于自启动项就认定恶意。'})}
 $wmis=@($raw.WMI|Where-Object {$_.Path -in $fs.Source -or (ContainsPath $_.Command $target)})
 foreach($w in $wmis){$verify.Add([pscustomobject]@{Question=('WMI对象与绑定：'+$w.Name);Command=('Get-CimInstance -Namespace root/subscription -ClassName '+(Q $w.Class)+' | Format-List *'+[Environment]::NewLine+'Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Format-List Filter,Consumer');Expected='对照消费者、过滤器与绑定三处引用；只读取ScriptText，不执行脚本。'})}
 $severity=if(@($fs|Where-Object Severity -eq '高').Count){'高'}else{'中'}
 $kind=if(@($fs|Where-Object Title -match 'IOC精确').Count){'哈希IOC命中'}elseif(@($fs|Where-Object Title -match 'DLL侧加载').Count){'侧加载候选'}elseif(@($fs|Where-Object Title -match '挖矿').Count){'挖矿行为线索'}else{'待核实对象'}
 $status=if($processes.Count){'快照中有运行实例'}elseif($connections.Count){'快照中有连接'}else{'未关联当前运行实例'}
 $objectPlan=New-Object 'Collections.Generic.List[object]'
 foreach($s in $persist){$objectPlan.Add([pscustomobject]@{Type=$s.Kind;Location=$s.Location;Name=$s.Name;Target=$s.Path;Command=$s.Command;Enabled=$s.Enabled;Principal=$s.Principal;State=$s.State;Extra=$s.Extra;Decision='仅在确认恶意性后，人工针对这个精确配置处置；本工具未变更。'})}
 foreach($w in $wmis){$objectPlan.Add([pscustomobject]@{Type='WMI';Location=$w.Path;Name=$w.Name;Target=$target;Command=$w.Command;Enabled='需核实绑定';Principal='未读取CreatorSID';State='永久消费者对象';Extra=$w.Script;Decision='确认恶意性后，人工定位消费者以及引用它的Filter/Binding；本工具未变更任何WMI对象。'})}
 foreach($file in $files){if($file.Path -ne $target -or ((SharedHost $target) -and !@($fs|Where-Object Title -match 'SHA256 IOC精确').Count)){continue};$objectPlan.Add([pscustomobject]@{Type='File';Location=$file.Path;Name='';Target=$file.Path;Command='';Enabled='';Principal='';State=('Exists='+$file.Exists+';Signature='+$file.Signature);Extra=('SHA256='+$file.SHA256);Decision='先保全并验证SHA256，确认这个文件本身恶意后人工处置；关联的合法宿主不因为加载了可疑DLL就列为清理对象。'})}
 $missing=@();if(!$eventRows.Count){$missing+='无关联历史事件，不能确认投放者或入口'};if(!$persist.Count){$missing+='未关联持久化配置；不等于无文件外的持久化'};if(!$files.Count){$missing+='缺少目标文件哈希/签名证据'};if(!$processes.Count){$missing+='未关联运行实例，不能据此指认当前活动进程'}
 $networkAdvice=if($connections.Count){'若恶意性或紧迫危害已确认，由值守人员评估业务后隔离这台主机；下面的远端仅是快照连接，未逐个确认C2，不能整批拉黑。'}else{'没有关联到当前已建立连接，暂未生成具体C2封堵对象。'}
 $exit=if($modules.Count){'复采已覆盖的模块清单，确认这个DLL没有再被加载；核对上述宿主实例与关联远端是否仍存在。'}else{'按上述PID的启动时间与映像路径复核运行实例，并核对关联远端；不要只比较PID数字。'}
 if($persist.Count){$exit+='逐项复核已确认恶意的配置（'+(($persist|ForEach-Object {$_.Kind+':'+$_.Location+' ['+$_.Name+']'}) -join ';')+'），确认不再启动原对象。'}
 $exit+='经业务允许重新登录或重启后再复采；入口未补证或证据覆盖不足时，不能宣称根除。'
 $cases.Add([pscustomobject]@{Id=('C{0:d2}' -f ($cases.Count+1));Target=$target;Kind=$kind;Severity=$severity;Verdict='尚未确认恶意性';State=$status;Trigger=@($fs.Title);EvidenceIds=$evidenceIds;Processes=$prows.ToArray();Files=$files;Persistence=$persist;Connections=$connections;HistoryEvents=$eventRows;Verification=$verify.ToArray();ManualObjects=$objectPlan.ToArray();Containment=$networkAdvice;MissingEvidence=$missing;ExitCriteria=$exit})
}
# 未确认成功处置的历史检测逐项保留资源，不把它当作当前感染结论。
foreach($t in $a.TransientExecutions){
 $fs=@($a.Findings|Where-Object Source -eq ('History: '+$t.Path))
 $persist=@($raw.Persistence|Where-Object {$_.Path -eq $t.Path -or (ContainsPath $_.Command $t.Path)})
 $cases.Add([pscustomobject]@{Id=('C{0:d2}' -f ($cases.Count+1));Kind='异常启动轨迹';ContextOnly=$true;Target=$t.Path;Severity=$t.Severity;Trigger=@($t.Conclusion);EvidenceIds=@($fs.Id);Timeline=$t;Persistence=$persist;Files=@($t.File);Processes=@();Connections=@();Verification=@();HistoryEvents=@();ManualObjects=@();State='历史启动与删除已记录；当前运行状态需看内存/进程结果';Verdict='发现异常行为组合，尚未证明恶意因果';MissingEvidence=@($t.Limit)})
}
foreach($m in $raw.Memory|Where-Object {$_.IdentityMatched -and $_.Hits.Count}){
 $fs=@($a.Findings|Where-Object Source -eq ('Memory: PID='+$m.Pid))
 $cases.Add([pscustomobject]@{Id=('C{0:d2}' -f ($cases.Count+1));Kind='内存异常';Target=$m.Path;Severity='中';Trigger=@('非映像可执行内存异常');EvidenceIds=@($fs.Id);Memory=$m;Processes=@($raw.Processes|Where-Object Pid -eq $m.Pid);Connections=@($raw.TCP|Where-Object Pid -eq $m.Pid);Persistence=@();Files=@();Verification=@();HistoryEvents=@();ManualObjects=@();State='同一进程实例已核对路径及启动时间';Verdict='需区分注入与合法动态代码';MissingEvidence=@('内存命中不证明磁盘宿主被篡改；不据此清理宿主文件')})
}
$pending=@($raw.Detections|Where-Object {$_.ThreatID -and $_.ActionSuccess -ne $true})
foreach($d in $pending){$diagnostics.Add([pscustomobject]@{Title='历史检测处置状态待确认';Location=('Defender ThreatID='+$d.ThreatID);Target=($d.Resources -join ';');Fact=('ActionSuccess='+$d.ActionSuccess);Next='核对资源现状与Defender处置记录，不能只按历史状态认定活跃感染。';Command='Get-MpThreatDetection | Select-Object ThreatID,Resources,ActionSuccess,CurrentThreatExecutionStatusID'})}
# Automatic pivots supersede a less informative card about the same target.
$auto=@($a.GeneralCases|Where-Object {$_});$combined=@($auto)+@($cases.ToArray()|Where-Object {$_.Target -notin $auto.Target -or $_.Kind -in @('内存异常','异常启动轨迹','异常安装链')})
$cases=New-Object 'Collections.Generic.List[object]';foreach($c in $combined){$c.Id=('C{0:d2}' -f ($cases.Count+1));$cases.Add($c)}
$schema=[pscustomobject]@{Version='1.9';CaseCount=$cases.Count;Cases=$cases.ToArray();Diagnostics=$diagnostics.ToArray();Decision=if($cases.Count){'存在可沿对象继续核查的线索；先执行对象级只读核验，再决定处置。'}else{'未定位到可指认的攻击对象；不能凭本报告选择进程、注册表、服务或文件实施安全清理。'};RequiredNext=if($cases.Count){'按每个对象的核验命令与判读标准推进，不把候选关系直接当攻击因果。'}else{'当前规则未定位异常；检查采集缺口和扩大日志回溯范围。'};Live=$Live.IsPresent;Scope='仅取证与对象级核查计划，无任何删除/清空/停进程/变更配置命令。'}
return $schema
