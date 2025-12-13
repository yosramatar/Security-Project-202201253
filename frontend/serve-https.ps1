param([string]$Cert = "192.168.56.1+2.pem", [string]$Key = "192.168.56.1+2-key.pem", [int]$Port = 8080)
Write-Host "Serving frontend over HTTPS on port $Port using cert=$Cert key=$Key"
Set-Location -Path (Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)
if (!(Test-Path $Cert)) { Write-Error "Certificate file not found: $Cert"; exit 1 }
if (!(Test-Path $Key))  { Write-Error "Key file not found: $Key"; exit 1 }
$npx = 'npx'
$args = @('http-server', '.', '-p', $Port.ToString(), '--ssl', '--cert', $Cert, '--key', $Key)
Write-Host "Running: $npx $($args -join ' ')"
& $npx $args
