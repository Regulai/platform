$ErrorActionPreference = 'Stop'
$taskInventory = [ordered]@{
    schema_version = 1
    observed_at_utc = [DateTime]::UtcNow.ToString('o')
    purpose = 'Read-only availability check for synthetic document pilot; no applications launched'
    path_commands = @()
    com_registrations = @()
    install_directories = @()
    uninstall_matches = @()
}
foreach ($taskCommand in @('WINWORD', 'EXCEL', 'soffice', 'libreoffice')) {
    $taskFound = Get-Command $taskCommand -ErrorAction SilentlyContinue
    $taskInventory.path_commands += [ordered]@{ name = $taskCommand; found = [bool]$taskFound; paths = @($taskFound | Select-Object -ExpandProperty Source) }
}
foreach ($taskProgId in @('Word.Application', 'Excel.Application', 'com.sun.star.ServiceManager')) {
    $taskInventory.com_registrations += [ordered]@{ prog_id = $taskProgId; found = Test-Path -LiteralPath "Registry::HKEY_CLASSES_ROOT\$taskProgId" }
}
foreach ($taskInstallPath in @('C:\Program Files\Microsoft Office', 'C:\Program Files (x86)\Microsoft Office', 'C:\Program Files\LibreOffice', 'C:\Program Files (x86)\LibreOffice')) {
    $taskInventory.install_directories += [ordered]@{ path = $taskInstallPath; found = Test-Path -LiteralPath $taskInstallPath }
}
foreach ($taskUninstallRoot in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    $taskInventory.uninstall_matches += @(Get-ItemProperty -Path $taskUninstallRoot -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Microsoft (365|Office|Word|Excel)|LibreOffice' } | Select-Object DisplayName, DisplayVersion, InstallLocation)
}
$taskInventory | ConvertTo-Json -Depth 8
