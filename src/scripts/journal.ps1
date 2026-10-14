function Get-JournalEvidence($History){
 $windows=@($History|Where-Object {$_.Path -ne $IRLauncher}|Sort-Object TimeUtc -Descending|Select-Object -First 12)
 if(!$windows.Count){return}
 if(!('YingJiJournal.Reader' -as [type])){throw '内嵌原生探测类型未加载'}
 foreach($group in $windows|Group-Object {$_.Path.Substring(0,2)}){
  $centers=[long[]]@($group.Group|ForEach-Object {([datetime]$_.TimeUtc).ToUniversalTime().ToFileTimeUtc()})
  $r=[YingJiJournal.Reader]::Read($group.Name,$centers,12000)
  if(!$r.Complete -or $r.Error -or $r.Unsupported){Gap ('文件变更日志 '+$group.Name) ('Complete='+$r.Complete+';Error='+$r.Error+';不支持记录='+$r.Unsupported+'；只读现有NTFS日志，不创建或修改日志')}
  [pscustomobject]@{Volume=$r.Volume;Error=$r.Error;Complete=$r.Complete;Records=$r.Records;Unsupported=$r.Unsupported;Windows=$group.Group;Changes=@($r.Changes)}
 }
}
