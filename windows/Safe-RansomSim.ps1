param([string]$Root="C:\Lab\RansomTest",[int]$Files=200,[switch]$Encrypt,[switch]$WriteEICAR,[switch]$Cleanup)
$ErrorActionPreference="Stop"
if($Cleanup){if(Test-Path $Root){Remove-Item $Root -Recurse -Force};Write-Host "Cleanup complete";exit}
$orig=Join-Path $Root "original";$work=Join-Path $Root "work";New-Item -ItemType Directory -Force -Path $orig,$work|Out-Null
$rand=New-Object Random
1..$Files|%{
  $p=Join-Path $orig ("file_{0:D4}.txt" -f $_)
  $bytes=New-Object byte[] ($rand.Next(2048,12288));$rand.NextBytes($bytes);[IO.File]::WriteAllBytes($p,$bytes)
}
Copy-Item "$orig\*" $work -Force
if($WriteEICAR){
  $a='X5O!P%@AP[4\PZX54(P^)7CC)7}';$b='$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
  $e=$a+$b; Set-Content -Path (Join-Path $work "eicar.com") -Value $e -Encoding ascii
}
$key=New-Object byte[] 32;$iv=New-Object byte[] 16;$rand.NextBytes($key);$rand.NextBytes($iv)
function Enc([byte[]]$d,[byte[]]$k,[byte[]]$i){$a=[Security.Cryptography.Aes]::Create();$a.Mode='CBC';$a.Key=$k;$a.IV=$i;$m=New-Object IO.MemoryStream;$c=New-Object Security.Cryptography.CryptoStream($m,$a.CreateEncryptor(),[Security.Cryptography.CryptoStreamMode]::Write);$c.Write($d,0,$d.Length);$c.FlushFinalBlock();$c.Dispose();$e=$m.ToArray();$m.Dispose();$a.Dispose();$e}
Get-ChildItem $work -File | %{
  $f=$_.FullName;$b=[IO.File]::ReadAllBytes($f)
  if($Encrypt){$b=Enc $b $key $iv}else{$rand.NextBytes($b)}
  [IO.File]::WriteAllBytes($f,$b);Rename-Item $f ($_.Name+".locked")
}
Write-Host "Simulation done. Cleanup: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Cleanup"
