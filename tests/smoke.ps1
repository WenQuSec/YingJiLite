param([Parameter(Mandatory=$true)][string]$Binary,[string]$Output)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Core'){throw 'Use Windows PowerShell 5.1'}
if(!$Output){$Output=Join-Path $PSScriptRoot ('test-output-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $Output){throw 'Use a new test output directory'}
New-Item -ItemType Directory -Path $Output | Out-Null
$assembly=[Reflection.Assembly]::LoadFile([IO.Path]::GetFullPath($Binary))
$harness=Join-Path $Output 'Replay.exe'
& (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') /nologo /target:exe /platform:x64 ('/out:'+$harness) (Join-Path $PSScriptRoot 'Replay.cs')
if($LASTEXITCODE){throw 'Replay harness compilation failed'}
foreach($name in @('YingJiFile.Probe','YingJiMemory.Reader','YingJiImage.Reader','YingJiJournal.Reader','YingJiStatic.Decode')){if(!$assembly.GetType($name)){throw ('Missing native type: '+$name)}}
function Assert($condition,$message){if(!$condition){throw $message}}
function SaveJson($path,$value){[IO.File]::WriteAllText($path,(ConvertTo-Json -InputObject $value -Depth 20),(New-Object Text.UTF8Encoding($true)))}
$time='2026-01-02T03:04:05.0000000Z'
$target='C:\ProgramData\SyntheticIR\worker.exe'
$safe='C:\Windows\System32\notepad.exe'
$service='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SyntheticWorker'
$registry='Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$required=@('进程','实时网络与进程身份观察','加载模块','进程内存','服务','注册表持久化','计划任务','启动目录','WMI永久订阅','启动目标与全部已加载模块验证','深度文件与网络线索','运行实例与外联追查')
function Fixture([bool]$suspicious,[bool]$complete){
 $path=if($suspicious){$target}else{$safe}
 $process=[pscustomobject]@{Pid=42420;ParentPid=0;Name=[IO.Path]::GetFileName($path);Path=$path;Command=if($suspicious){'"'+$path+'" --coin monero --donate-level 0'}else{$path};StartUtc=$time}
 $observation=[pscustomobject]@{StartUtc=$time;EndUtc='2026-01-02T03:04:35.0000000Z';TraceStatus=if($complete){'完成'}else{'未采集'};DNSEvents=@();SocketEvents=@();Processes=@();RequestedSeconds=30}
 $memory=[pscustomobject]@{Pid=42420;Path=$path;StartUtc=$time;Opened=$true;Complete=$true;IdentityMatched=$true;ReadFailures=0;ThreadFailures=0;Hits=@()}
 $metadata=[pscustomobject]@{Path=$path;Exists=$true;Size=1024;CreatedUtc=$time;ModifiedUtc=$time;Signature=if($suspicious){'NotSigned'}else{'Valid'};SHA256=('1'*64);HiddenParent=$false;Error='';OriginalFilename=[IO.Path]::GetFileName($path);CompanyName='Synthetic fixture'}
 $persist=if($suspicious){@(
  [pscustomobject]@{Kind='Service';Location=$service;Name='SyntheticWorker';Command=('"'+$target+'"');Path=$target;Enabled=$true;Principal='LocalSystem';State='Running';Extra='Synthetic';Pid=42420},
  [pscustomobject]@{Kind='Run/RunOnce';Location=$registry;Name='SyntheticWorker';Command=('"'+$target+'"');Path=$target;Enabled=$true;Principal='System';Extra='Synthetic'},
  [pscustomobject]@{Kind='Service';Location='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SyntheticUnrelated';Name='SyntheticUnrelated';Command=$safe;Path=$safe;Enabled=$true;Principal='LocalSystem';Extra='Benign fixture'}
 )}else{@()}
 $tcp=if($suspicious){@([pscustomobject]@{Pid=42420;LocalAddress='192.0.2.10';LocalPort=50000;RemoteAddress='192.0.2.44';RemotePort=4444;State='Established';IdentityMatched=$true;TimeUtc=$time})}else{@()}
 $events=if($suspicious){@([pscustomobject]@{Log='Microsoft-Windows-Sysmon/Operational';Id=22;RecordId=12;TimeUtc=$time;Data=@{Image=$target;ProcessId='42420';ProcessGuid='{00000000-0000-0000-0000-000000000001}';QueryName='demo-c2.invalid';QueryStatus='0';QueryResults='192.0.2.44'}})}else{@()}
 return [pscustomobject]@{
  Host=[pscustomobject]@{Computer='SYNTHETIC';User='fixture';Admin=$complete;OS='Synthetic Windows';TimeUtc=$time;SystemRoot='C:\Windows';Version='1.13';Mode='Synthetic replay';CollectorPath='C:\Synthetic\YingJiLite.exe'}
  Processes=@($process);Persistence=@($persist);Files=@($metadata);TCP=@($tcp);UDP=@();DNS=@();Events=@($events);Modules=@();WMI=@();Users=@();Admins=@();Defender=@();Exclusions=@();Detections=@();RecentFiles=@();Packages=@();Memory=@($memory);ExecutionHistory=@();Journals=@();Crashes=@();ImageIntegrity=@()
  General=[pscustomobject]@{Scripts=@();PersistencePivots=@();Directories=@();RelatedFiles=@()}
  Investigation=[pscustomobject]@{DeepFiles=@();StaticNetwork=@()}
  Runtime=[pscustomobject]@{Identity=@{'42420'=$true};Connections=@($tcp);NetworkObservation=$observation}
  Coverage=@($required|ForEach-Object {[pscustomobject]@{Module=$_;Status='成功';Count=1;Detail='Synthetic fixture';Seconds=0}})
 }
}
foreach($scenario in @('suspicious','incomplete','healthy')){
 $fixture=Fixture ($scenario -eq 'suspicious') ($scenario -ne 'incomplete')
 $inputFile=Join-Path $Output ($scenario+'.json');SaveJson $inputFile $fixture
 $report=Join-Path $Output $scenario
 & $harness ([IO.Path]::GetFullPath($Binary)) ([IO.Path]::GetFullPath($report)) ([IO.Path]::GetFullPath($inputFile))
 $code=$LASTEXITCODE
 Assert ($code -eq 0) ('Replay failed: '+$scenario)
 $view=Get-Content -LiteralPath (Join-Path $report 'report-view.json') -Raw -Encoding UTF8|ConvertFrom-Json
 $expected=switch($scenario){'suspicious'{'red'}'incomplete'{'yellow'}'healthy'{'green'}}
 Assert ($view.AssessmentLevel -eq $expected) ('Unexpected assessment: '+$scenario+' '+$view.AssessmentLevel)
 if($scenario -eq 'suspicious'){
  $plan=Get-Content -LiteralPath (Join-Path $report 'response-plan.json') -Raw -Encoding UTF8|ConvertFrom-Json
  $case=@($plan.Cases|Where-Object Target -eq $target)
  Assert ($case.Count -eq 1) 'Failed to identify synthetic payload'
  Assert (@($case[0].Persistence|Where-Object Location -eq $service).Count -eq 1) 'Service location missing'
  Assert (@($case[0].Persistence|Where-Object Location -eq $registry).Count -eq 1) 'Registry location missing'
  Assert (@($case[0].Persistence|Where-Object Name -eq 'SyntheticUnrelated').Count -eq 0) 'Unrelated service incorrectly associated'
  Assert (@($case[0].Connections|Where-Object RemoteAddress -eq '192.0.2.44').Count -ge 1) 'Network connection missing'
  $network=Get-Content -LiteralPath (Join-Path $report 'network-evidence.json') -Raw -Encoding UTF8|ConvertFrom-Json
  Assert (@($network.Rows|Where-Object {$_.Value -eq 'demo-c2.invalid' -and $_.Process -eq $target}).Count -eq 1) 'Historical DNS process identity missing'
 }
 $dropped=@(Get-ChildItem -LiteralPath $report -Recurse -File|Where-Object Extension -in @('.ps1','.cs','.dll','.exe','.bat','.cmd'))
 Assert ($dropped.Count -eq 0) 'Executable code was dropped in report output'
 $manifest=Get-Content -LiteralPath (Join-Path $report 'manifest.json') -Raw -Encoding UTF8|ConvertFrom-Json
 foreach($entry in $manifest){Assert ((Get-FileHash -LiteralPath (Join-Path $report $entry.Name) -Algorithm SHA256).Hash -eq $entry.SHA256) ('Manifest hash mismatch: '+$entry.Name)}
 Write-Host ('PASS '+$scenario)
}
Write-Host ('Synthetic tests passed. Retained output: '+$Output)
