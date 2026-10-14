# Read-only static inspection. Never install, extract, load or execute package content.
function Test-LocalArtifact([string]$Path) {
 if($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')){return $false}
 try {
  if(([IO.DriveInfo]::new($Path.Substring(0,3))).DriveType -ne 'Fixed'){return $false}
  $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  while($item){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){return $false};$item=if($item.PSIsContainer){$item.Parent}else{$item.Directory}}
  return $true
 }catch{return $false}
}
function Test-PeHeader([byte[]]$Bytes,[long]$Length) {
 if($Bytes.Length -lt 96 -or $Bytes[0] -ne 77 -or $Bytes[1] -ne 90){return $false}
 $off=[BitConverter]::ToInt32($Bytes,60)
 if($off -lt 64 -or $off -gt $Bytes.Length-26){return $false}
 if([BitConverter]::ToUInt32($Bytes,$off) -ne 17744){return $false}
 $machine=[BitConverter]::ToUInt16($Bytes,$off+4);$sections=[BitConverter]::ToUInt16($Bytes,$off+6)
 $opt=[BitConverter]::ToUInt16($Bytes,$off+20);$magic=[BitConverter]::ToUInt16($Bytes,$off+24)
 return ($machine -in @(332,34404,43620) -and $sections -ge 1 -and $sections -le 96 -and $opt -ge 96 -and $opt -le 512 -and $magic -in @(267,523) -and ($off+24+$opt+40*$sections) -le $Length)
}
function Initialize-IRFileProbe {
 if('YingJiFile.Probe' -as [type]){return}
 throw '内嵌原生探测类型未加载'
}
function Read-ContentShape([string]$Path) {
 $r=[ordered]@{Kind='Other';Detail='';Entries=@();Error='';XorKey=@()}
 $stream=$null
 try {
  $stream=[IO.File]::Open($Path,'Open','Read','ReadWrite');$length=$stream.Length
  $bytes=New-Object byte[] ([Math]::Min($length,65536));$n=0
  while($n -lt $bytes.Length){$read=$stream.Read($bytes,$n,$bytes.Length-$n);if(!$read){break};$n+=$read}
  $ext=[IO.Path]::GetExtension($Path)
  Initialize-IRFileProbe;$probe=[YingJiFile.Probe]::Inspect($bytes,$length)
  if($probe.Kind -eq 'PE'){$r.Kind='PE';if($ext -notmatch '^\.(exe|dll|sys|scr|ocx|cpl|drv|efi|mui|tlb|winmd|olb|fon)$'){$r.Kind='DisguisedPE';$r.Detail='扩展名与内容不符：文件具有完整 PE 头结构。'}}
  elseif($probe.Kind -eq 'EncodedPE' -and $ext -notmatch '^\.(exe|dll|sys|scr|ocx|cpl|drv|efi|mui|tlb|winmd|olb|fon)$'){$r.Kind='EncodedPE';$r.XorKey=@($probe.Key);$r.Detail='非程序扩展名下藏有循环 XOR 编码 PE；密钥='+[BitConverter]::ToString($probe.Key)+'；DOS、PE、COFF、可选头结构通过校验（仅内存读取头部）。'}
  if($bytes.Length -ge 4 -and [BitConverter]::ToUInt32($bytes,0) -eq 67324752 -and $ext -match '^\.(png|jpg|jpeg|gif|bmp|ico|xml|txt|dat|tmp)$'){
   $r.Kind='DisguisedZip';$r.Detail='扩展名与内容不符：实际为 ZIP。'
   if($length -le 64MB){
    Add-Type -AssemblyName System.IO.Compression
    $stream.Position=0;$zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Read,$true)
    try {$r.Entries=@($zip.Entries|Select-Object -First 256|ForEach-Object {[pscustomobject]@{Name=$_.FullName;Length=$_.Length;CompressedLength=$_.CompressedLength}})}finally{$zip.Dispose()}
    if(@($r.Entries|Where-Object Name -match '\.(exe|dll|sys|ps1|vbs|js|hta|scr)$').Count){$r.Kind='DisguisedZipWithCode';$r.Detail='图片/文本扩展名下实际是 ZIP，并包含程序或脚本；只列目录，未解压。'}
   }else{$r.Error='超过64MB，未枚举ZIP目录'}
  }
 }catch{$r.Error=$_.Exception.Message}finally{if($stream){$stream.Dispose()}}
 return [pscustomobject]$r
}
function Read-MsiTable($Db,[string]$Table) {
 $view=$null
 try {
  $view=$Db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$Db,@('SELECT * FROM `'+$Table+'`'))
  $null=$view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null)
  $col=$view.GetType().InvokeMember('ColumnInfo','GetProperty',$null,$view,@(0))
  $count=$col.GetType().InvokeMember('FieldCount','GetProperty',$null,$col,$null)
  $names=@();for($i=1;$i -le $count;$i++){$names+=$col.GetType().InvokeMember('StringData','GetProperty',$null,$col,@($i))}
  $rows=0
  while($rows -lt 2000){
   $rec=$view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null);if(!$rec){break}
   $row=[ordered]@{};for($i=1;$i -le $count;$i++){$row[$names[$i-1]]=$rec.GetType().InvokeMember('StringData','GetProperty',$null,$rec,@($i))};[pscustomobject]$row;$rows++
  }
  if($rows -ge 2000){Gap ('MSI表 '+$Table) '达到2000行读取上限'}
 }finally{if($view){$null=$view.GetType().InvokeMember('Close','InvokeMethod',$null,$view,$null)}}
}
function Get-ArtifactSignals($File,$Actions) {
 $signals=@()
 if($File.Shape.Kind -eq 'EncodedPE'){$signals+='编码隐藏可执行文件'}
 if($File.Shape.Kind -eq 'DisguisedPE'){$signals+='伪装扩展名的可执行文件'}
 if($File.Shape.Kind -eq 'DisguisedZipWithCode'){$signals+='伪装图片或文本的程序压缩包'}
 if($File.Signature -eq 'HashMismatch' -and @($Actions).Count){$signals+='安装动作引用签名被破坏的文件'}
 return $signals
}
function Get-InstallEventPaths([string]$XmlText){
 $xml=[xml]$XmlText
 foreach($node in $xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']")){
  $p=([string]$node.InnerText).Trim('"',' ')
  if($p -match '^[A-Za-z]:\\.*\.msi$'){$p}
 }
}
function Get-AutomaticPackages([int]$Hours=72) {
 $timer=[Diagnostics.Stopwatch]::StartNew();$paths=New-Object 'Collections.Generic.List[object]';$events=@();$seen=@{};$contentCache=@{};$fileCount=0;$hashBytes=0L
 try {
  $events=@(Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='MsiInstaller';Id=@(1040,1042,1033,11707);StartTime=(Get-Date).AddHours(-$Hours)} -MaxEvents 400 -ErrorAction Stop|ForEach-Object {[pscustomobject]@{Log='Application';Id=$_.Id;RecordId=$_.RecordId;TimeUtc=$_.TimeCreated.ToUniversalTime().ToString('o');Message=$_.Message;Xml=$_.ToXml()}})
  $script:packageEvents=$events
  foreach($e in $events|Where-Object Id -in @(1040,1042)){
   foreach($p in @(Get-InstallEventPaths $e.Xml)){$paths.Add([pscustomobject]@{Path=$p;Origin=('Application#'+$e.RecordId);Event=$e})}
  }
 }catch {if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound'){Gap '安装事件' $_.Exception.Message}}
 # Cached packages are secondary. No Windows Installer repair or install API is called.
 try {
  $registered=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties' -ErrorAction Stop|Get-ItemProperty|Sort-Object InstallDate -Descending|Select-Object -First 12)
  foreach($p in $registered){if($p.LocalPackage){$paths.Add([pscustomobject]@{Path=[string]$p.LocalPackage;Origin=[string]$p.PSPath;Event=$null})}}
 }catch {Gap '安装缓存索引' $_.Exception.Message}
 $installer=New-Object -ComObject WindowsInstaller.Installer
 foreach($candidate in $paths){
  $path=$candidate.Path;if($seen.ContainsKey($path)){continue};$seen[$path]=$true
  if($seen.Count -gt 16 -or $timer.Elapsed.TotalSeconds -gt 90){Gap '安装链预算' '达到16包或90秒预算；其余安装包未检查';break}
  $pkg=[ordered]@{Path=$path;Origin=$candidate.Origin;Product='';ProductCode='';Events=@($events|Where-Object {$_.Message -and $_.Message.IndexOf($path,[StringComparison]::OrdinalIgnoreCase) -ge 0});Actions=@();Files=@();Signals=@();Errors=@()}
  $db=$null
  try {
   if(!(Test-LocalArtifact $path)){throw '安装源不存在、不是本地固定磁盘文件或经过重解析点；跳过'}
   if((Get-Item -LiteralPath $path).Length -gt 512MB){throw '安装包超过512MB预算'}
   $db=$installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($path,0))
   $props=@(Read-MsiTable $db 'Property');$pkg.Product=(@($props|Where-Object Property -eq 'ProductName')|Select-Object -First 1).Value;$pkg.ProductCode=(@($props|Where-Object Property -eq 'ProductCode')|Select-Object -First 1).Value
   if($pkg.Product){$pkg.Events+=@($events|Where-Object {$_.Id -in @(1033,11707) -and $_.Message.IndexOf($pkg.Product,[StringComparison]::OrdinalIgnoreCase) -ge 0})}
   $files=@(Read-MsiTable $db 'File');$components=@(Read-MsiTable $db 'Component')
   try{$actions=@(Read-MsiTable $db 'CustomAction')}catch{$actions=@()}
   try{$sequence=@(Read-MsiTable $db 'InstallExecuteSequence')}catch{$sequence=@()}
   $pkg.Actions=@($actions|ForEach-Object {$act=$_;$seq=@($sequence|Where-Object Action -eq $act.Action);[pscustomobject]@{Action=$act.Action;Type=$act.Type;Source=$act.Source;Target=$act.Target;Sequence=$seq}})
   $componentPaths=@{}
   foreach($comp in $components){
    if($timer.Elapsed.TotalSeconds -gt 90){$pkg.Errors+='安装链90秒预算已到';break}
    if(!$comp.ComponentId -or ([int]$comp.Attributes -band 4)){continue}
    try{$p=$installer.GetType().InvokeMember('ComponentPath','GetProperty',$null,$installer,@($pkg.ProductCode,$comp.ComponentId));if($p -match '^[A-Za-z]:\\'){$componentPaths[$comp.Component]=[pscustomobject]@{Path=$p;KeyPath=$comp.KeyPath}}}catch{$pkg.Errors+=('组件定位失败: '+$comp.Component)}
   }
   foreach($f in $files){
    if($timer.Elapsed.TotalSeconds -gt 90){$pkg.Errors+='安装链90秒预算已到';break}
    $comp=$componentPaths[$f.Component_];if(!$comp){continue}
    $name=([string]$f.FileName -split '\|')[-1];if(!$name -or $name -match '[\\/:]' -or $name -in @('.','..')){continue}
    $p=if($f.File -eq $comp.KeyPath){$comp.Path}else{Join-Path ([IO.Path]::GetDirectoryName($comp.Path)) $name}
    if(!(Test-LocalArtifact $p)){$pkg.Errors+=('文件不存在或不能安全读取: '+$p);continue}
    if(!$contentCache.ContainsKey($p)){
     if($fileCount -ge 400){$pkg.Errors+='安装文件检查达到400个不同文件预算';break}
     $fileCount++;$contentCache[$p]=Read-ContentShape $p
    }
    $m=Meta $p;$shape=$contentCache[$p]
    $ref=@($pkg.Actions|Where-Object {([string]$_.Target).Contains('[#'+$f.File+']') -or (([int]$_.Type -band 0x30) -eq 0x10 -and $_.Source -eq $f.File)})
    $obj=[pscustomobject]@{Path=$p;FileId=$f.File;Exists=$m.Exists;Size=$m.Size;SHA256=$m.SHA256;Signature=$m.Signature;Signer=$m.Signer;Shape=$shape;ActionRefs=$ref;Signals=@();Error=$m.Error}
    $obj.Signals=@(Get-ArtifactSignals $obj $ref);$pkg.Files+=@($obj)
    if($obj.Signals.Count){$pkg.Signals+=$obj.Signals}
   }
   if($pkg.Signals.Count){
    # Hash only flagged package chains with a separate total I/O cap.
    foreach($p in @($path)+@($pkg.Files|Where-Object {$_.Signals.Count}|Select-Object -ExpandProperty Path)){
     $m=Meta $p
     if(!$m.SHA256 -and $m.Size -le 512MB -and $hashBytes+$m.Size -le 1GB){$m.SHA256=HashFile $p;$hashBytes+=$m.Size}
    }
   }
  }catch{$pkg.Errors+=$_.Exception.Message}
  finally{if($db -and [Runtime.InteropServices.Marshal]::IsComObject($db)){$null=[Runtime.InteropServices.Marshal]::ReleaseComObject($db)}}
  if($pkg.Errors.Count){Gap ('安装检查 '+$path) ($pkg.Errors -join '; ')}
  [pscustomobject]$pkg
 }
 Gap '安装链检查范围' ('按最近'+$Hours+'小时安装事件及最多12个缓存包自动定位；最多16包/400文件/90秒，实际检查'+$fileCount+'文件；不覆盖所有非MSI安装及已删除的安装源。')
}
