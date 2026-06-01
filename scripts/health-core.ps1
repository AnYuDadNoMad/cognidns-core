$ErrorActionPreference = "Stop"
$body = curl.exe -s -o - http://127.0.0.1:8080/health
$status = curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8080/health
Write-Output $body
Write-Output "HTTP:$status"
if ($status -ne "200") { exit 1 }
