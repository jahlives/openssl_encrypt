# bw_unlock.ps1 — Unlock Bitwarden using openssl_encrypt to decrypt the master password
#
# Usage: .\bw_unlock.ps1
# Decrypts the master password, copies it to clipboard, launches Bitwarden, then clears clipboard.

$ENCRYPT_EXE = "C:\Users\jahli\git\openssl_encrypt\.venv\Scripts\openssl-encrypt.exe"
$MASTER_FILE = "Z:\Passwords\master.txt"

try {
    # Decrypt the master password directly to stdout — never touches disk
    $master_pw = (& $ENCRYPT_EXE decrypt -i $MASTER_FILE --no-estimate --progress)

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Failed to decrypt master password (exit code: $LASTEXITCODE)" -ForegroundColor Red
        exit 1
    }

    if (-not $master_pw) {
        Write-Host "Decryption produced no output" -ForegroundColor Red
        exit 1
    }

    # Copy master password to clipboard
    Set-Clipboard -Value $master_pw
    Write-Host "Master password copied to clipboard." -ForegroundColor Green

    # Launch Bitwarden desktop UI if not already running
    $bwProcess = Get-Process -Name "Bitwarden" -ErrorAction SilentlyContinue
    if (-not $bwProcess) {
        Start-Process "$env:LOCALAPPDATA\Programs\Bitwarden\Bitwarden.exe"
        Write-Host "Bitwarden started. Paste your master password with Ctrl+V." -ForegroundColor Green
    } else {
        Write-Host "Bitwarden is already running. Paste your master password with Ctrl+V." -ForegroundColor Green
    }

    # Wait for Ctrl+V (paste) then clear clipboard, with 25s timeout
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;

    public class PasteDetector {
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int vKey);

        private const int VK_CONTROL = 0x11;
        private const int VK_V = 0x56;

        public static bool WaitForPaste(int timeoutSeconds) {
            DateTime deadline = DateTime.Now.AddSeconds(timeoutSeconds);
            while (DateTime.Now < deadline) {
                short ctrlState = GetAsyncKeyState(VK_CONTROL);
                short vState = GetAsyncKeyState(VK_V);
                // Both keys currently pressed (high bit set)
                if ((ctrlState & 0x8000) != 0 && (vState & 0x8000) != 0) {
                    return true;
                }
                Thread.Sleep(50);
            }
            return false;
        }
    }
"@

    Write-Host "Waiting for paste (Ctrl+V) to clear clipboard (25s timeout)..." -ForegroundColor DarkGray
    $pasted = [PasteDetector]::WaitForPaste(25)
    if ($pasted) {
        Start-Sleep -Milliseconds 500  # Let the paste complete
    }
    Set-Clipboard -Value " "
    Write-Host "Clipboard cleared." -ForegroundColor Yellow

} finally {
    # Clear sensitive variables from memory
    Remove-Variable -Name master_pw -ErrorAction SilentlyContinue
}
