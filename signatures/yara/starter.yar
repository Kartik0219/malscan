/*
 * malscan starter rules.
 * These are intentionally simple, well-understood detections suitable for a
 * local scanner demo. Real-world deployments would pull from curated rule
 * feeds (e.g. YARA-Rules, Florian Roth's signature-base).
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test string (harmless industry test file)"
        severity    = "malicious"
        reference   = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Download_Exec
{
    meta:
        description = "PowerShell download-and-execute one-liner pattern"
        severity    = "suspicious"
        attack      = "T1059.001, T1105"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $iex = "IEX" nocase
        $inv = "Invoke-Expression" nocase
        $web = "Net.WebClient" nocase
    condition:
        $web and ($iex or $inv) and ($dl1 or $dl2)
}

rule Embedded_Windows_Executable_In_Script
{
    meta:
        description = "Base64-looking MZ/PE header embedded in a text/script file"
        severity    = "suspicious"
        attack      = "T1027"
    strings:
        $mz_b64 = "TVqQAA"   // base64 of "MZ\x90\x00"
        $mz_b64b = "TVpQAA"
    condition:
        any of them
}
