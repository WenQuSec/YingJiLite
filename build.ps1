param([string]$Destination, [string]$Python='python')
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -eq 'Core'){throw 'Run with Windows PowerShell 5.1 (powershell.exe), not pwsh.'}
$root=$PSScriptRoot
if(!$Destination){$Destination=Join-Path $root ('build-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))}
$Destination=[IO.Path]::GetFullPath($Destination)
if(Test-Path -LiteralPath $Destination){throw 'Output exists. Choose a new directory to preserve existing files.'}
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$wpf=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF'
$sma=Join-Path $env:WINDIR 'Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll'
foreach($path in @($compiler,$sma,(Join-Path $wpf 'PresentationFramework.dll'))){if(!(Test-Path -LiteralPath $path)){throw ('Required Windows component missing: '+$path)}}
foreach($file in Get-ChildItem -LiteralPath (Join-Path $root 'src\scripts') -Filter '*.ps1'){
 $tokens=$null;$errors=$null
 $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
}
New-Item -ItemType Directory -Path $Destination | Out-Null
$payload=Join-Path $Destination 'payload.bin'
& $Python (Join-Path $root 'tools\pack_scripts.py') --output $payload
if($LASTEXITCODE){throw 'Script resource packaging failed'}
$assets=Join-Path $root 'assets'
$resources=@('/resource:'+$payload+',payload.bin')
$resources+=@('brand-on-light.png','app.ico','Ui.xaml','icons.json')|ForEach-Object {'/resource:'+(Join-Path $assets $_)+','+$_}
$sources=@((Join-Path $root 'src\Launcher.cs'),(Join-Path $root 'src\Collector.cs'))+@(Get-ChildItem -LiteralPath (Join-Path $root 'src\native') -Filter '*.cs'|ForEach-Object {$_.FullName})
$binary=Join-Path $Destination 'YingJiLite.exe'
& $compiler /nologo /target:winexe /platform:x64 /optimize+ /reference:System.Web.Extensions.dll /reference:System.IO.Compression.dll /reference:System.Xaml.dll ('/reference:'+$sma) ('/reference:'+(Join-Path $wpf 'WindowsBase.dll')) ('/reference:'+(Join-Path $wpf 'PresentationCore.dll')) ('/reference:'+(Join-Path $wpf 'PresentationFramework.dll')) ('/win32manifest:'+(Join-Path $assets 'app.manifest')) ('/win32icon:'+(Join-Path $assets 'app.ico')) @resources ('/out:'+$binary) @sources
if($LASTEXITCODE){throw 'Compilation failed'}
Get-FileHash -LiteralPath $binary -Algorithm SHA256
Write-Output ('Deliver only: '+$binary)
