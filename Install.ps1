# Vérification de la version de PowerShell
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "Ce script nécessite PowerShell version 5.0 ou supérieure."
    exit
}

# Définition des variables
$pythonDownloadUrl = "https://www.python.org/ftp/python/3.13.0/python-3.13.0a4-amd64.exe"
$npcapDownloadUrl = "https://npcap.com/dist/npcap-1.79.exe"
$nmapDownloadUrl = "https://nmap.org/dist/nmap-7.94-setup.exe"
$gitDownloadUrl = "https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/Git-2.44.0-64-bit.exe"
$pythonInstallerPath = "C:\Temp\python-3.13.0-amd64.exe"
$npcapInstallerPath = "C:\Temp\npcap-1.79.exe"
$nmapInstallerPath = "C:\Temp\nmap-7.94-setup.exe"
$gitInstallerPath = "C:\Temp\Git-2.44.0-64-bit.exe"

# Création du dossier Temp s'il n'existe pas
if (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp"
}

# Vérification si Python est déjà installé et si le chemin est dans le PATH
$pythonInstalled = $false
$pythonPath = "C:\Python313"
$envPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
if (Test-Path $pythonPath) {
    $pythonInstalled = $true
    Write-Host "Python est déjà installé."
    if ($envPath -notcontains $pythonPath) {
        Write-Host "Ajout de Python au PATH."
        $env:Path += ";$pythonPath"
        [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    } else {
        Write-Host "Python est déjà dans le PATH."
    }
}

# Téléchargement de l'installateur Python si Python n'est pas installé
if (-not $pythonInstalled) {
    Invoke-WebRequest -Uri $pythonDownloadUrl -OutFile $pythonInstallerPath -UseBasicParsing
    Write-Host "L'installateur Python a été téléchargé."
}

Invoke-WebRequest -Uri $npcapDownloadUrl -OutFile $npcapInstallerPath -UseBasicParsing

# Vérification si Nmap est déjà installé et si le chemin est dans le PATH
$nmapInstalled = $false
$nmapPath = "C:\Program Files (x86)\Nmap"
if (Test-Path $nmapPath) {
    $nmapInstalled = $true
    Write-Host "Nmap est déjà installé."
    if ($envPath -notcontains $nmapPath) {
        Write-Host "Ajout de Nmap au PATH."
        $env:Path += ";$nmapPath"
        [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    } else {
        Write-Host "Nmap est déjà dans le PATH."
    }
}

# Téléchargement de l'installateur Nmap si Nmap n'est pas installé
if (-not $nmapInstalled) {
    Invoke-WebRequest -Uri $nmapDownloadUrl -OutFile $nmapInstallerPath -UseBasicParsing
    Write-Host "L'installateur Nmap a été téléchargé."
}

# Vérification si Git est déjà installé et si le chemin est dans le PATH
$gitInstalled = $false
$gitPath = "C:\Program Files\Git"
if (Test-Path $gitPath) {
    $gitInstalled = $true
    Write-Host "Git est déjà installé."
    if ($envPath -notcontains $gitPath) {
        Write-Host "Ajout de Git au PATH."
        $env:Path += ";$gitPath\cmd"
        [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    } else {
        Write-Host "Git est déjà dans le PATH."
    }
}

# Téléchargement de l'installateur Git si Git n'est pas installé
if (-not $gitInstalled) {
    Invoke-WebRequest -Uri $gitDownloadUrl -OutFile $gitInstallerPath -UseBasicParsing
    Write-Host "L'installateur Git a été téléchargé."
}

Write-Host "Les installateurs ont été téléchargés dans le dossier C:\Temp."


# Vérification de Python
$pythonExePath = "C:\Python313\python.exe"
if (Test-Path $pythonExePath) {
    Write-Host "Python est déjà installé."
} else {
    # Installation de Python
    Start-Process -FilePath $pythonInstallerPath -Args '/quiet TargetDir="C:\Python313"' -NoNewWindow -Wait

    Write-Host "Python a été installé avec succès."
}

# Installation de Npcap
Start-Process -FilePath $npcapInstallerPath -NoNewWindow -Wait

Write-Host "Npcap a été installé avec succès."

# Vérification de Nmap
$nmapExePath = "C:\Program Files\Nmap\nmap.exe"
if (Test-Path $nmapExePath) {
    Write-Host "Nmap est déjà installé."
} else {
    # Installation de Nmap
    Start-Process -FilePath $nmapInstallerPath -Args "/S" -NoNewWindow -Wait

    Write-Host "Nmap a été installé avec succès."
}

# Vérification de Git
$gitExePath = "C:\Program Files\Git\cmd\git.exe"
if (Test-Path $gitExePath) {
    Write-Host "Git est déjà installé."
} else {
    # Installation de Git
    Start-Process -FilePath $gitInstallerPath -Args "/VERYSILENT /NORESTART" -NoNewWindow -Wait

    Write-Host "Git a été installé avec succès."
}

# Vérification de la variable d'environnement PATH
if ($env:Path -notcontains "C:\Python313") {
    $env:Path += ";C:\Python313"
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    Write-Host "Python a été ajouté au PATH."
}

if ($env:Path -notcontains "C:\Program Files\Nmap") {
    $env:Path += ";C:\Program Files\Nmap"
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    Write-Host "Nmap a été ajouté au PATH."
}

if ($env:Path -notcontains "C:\Program Files\Git\cmd") {
    $env:Path += ";C:\Program Files\Git\cmd"
    [System.Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::User)
    Write-Host "Git a été ajouté au PATH."
}


# Vérification des installations
Write-Host "Python version :" (Get-Item "C:\Python313\python.exe").VersionInfo.FileVersion
Write-Host "Nmap version :" (Get-Item "C:\Program Files (x86)\Nmap\nmap.exe").VersionInfo.FileVersion
Write-Host "Git version :" (Get-Command git).Version.ToString()

# Clonage d'un dépôt GitHub
$repoUrl = "https://gitlab.com/msprs/TPRE511.git" # Remplacez par l'URL de votre dépôt
$destinationPath = "C:\Users\$env:USERNAME\Desktop\Seahawks" # Remplacez par le chemin où vous souhaitez cloner le dépôt

# Création du dossier de destination s'il n'existe pas
if (-not (Test-Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath
}

# Exécution de git clone
Start-Process -FilePath "git" -ArgumentList "clone", $repoUrl, $destinationPath -NoNewWindow -Wait

Write-Host "Le dépôt a été cloné avec succès dans le dossier: $destinationPath."

# Message de fin
Write-Host "L'installation de Python, Nmap, Git et le clonage du dépôt GitHub sont terminés."


# Ajout d'une pause avant de lancer l'application Python
Write-Host "Pour lancer l'application, appuyez sur Entrée."
Read-Host

# Lancement du script Python
$pythonPath = "python" # Assurez-vous que ceci pointe vers l'emplacement de votre interpréteur Python
$scriptPath = Join-Path -Path $destinationPath -ChildPath "Seahawks_Harvester\SeahawksHarvester.py"
Start-Process -FilePath $pythonPath -Args "`"$scriptPath`" `"$destinationPath`"" -NoNewWindow -Wait

