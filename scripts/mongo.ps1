# Start local MongoDB for Mirage (127.0.0.1:27017, data in D:\mongodb\data).
# Atlas is unusable on this network (port 27017 is blocked outbound); local Mongo uses loopback.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\mongo.ps1
$mongod = "D:\mongodb\mongodb-win32-x86_64-windows-7.0.43\bin\mongod.exe"
if (Get-Process mongod -ErrorAction SilentlyContinue) {
  Write-Output "mongod already running"
} else {
  New-Item -ItemType Directory -Force -Path "D:\mongodb\data","D:\mongodb\log" | Out-Null
  Start-Process -FilePath $mongod -ArgumentList @(
    "--dbpath","D:\mongodb\data","--port","27017","--bind_ip","127.0.0.1",
    "--logpath","D:\mongodb\log\mongod.log","--logappend") -WindowStyle Hidden
  Start-Sleep -Seconds 4
  Write-Output ("mongod started, pid " + (Get-Process mongod).Id)
}
