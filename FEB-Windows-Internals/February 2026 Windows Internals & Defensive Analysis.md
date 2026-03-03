* * *

# 2026 Lockin Program: Month 2 - Windows Internals & Defensive Analysis

## Summary

Deep-dive telemetry analysis within the Windows ecosystem was the focus of this month. I looked into the basic Active Directory authentication procedures, improved visibility with Sysmon, and the workings of Windows Event Logging. The objective was to close the gap between "seeing" an attack's footprint in the logs and "knowing" it happens.

* * *

## Week 5: Windows Event Logs Core

**Objective:** Master the identification and categorization of native Windows events to detect unauthorized access.

### Technical Analysis

Windows Event Logs are categorized into primary logs like **Application**, **System**, and **Security**. During this phase, I focused on the "Anatomy of an Event," specifically leveraging **Keywords** for filtering precision and **Logon IDs** to correlate related events.

### Key Event IDs Mastered:

- **4624 (Successful Logon):** Essential for establishing baseline user behavior.
    
- **4625 (Failed Logon):** Primary indicator for identifying brute-force attempts.
    
- **1102 (Audit Log Cleared):** A critical alert for identifying anti-forensics or evidence tampering.
    
- **4698 / 4702 (Scheduled Tasks):** Monitoring for common persistence mechanisms.
    

### Deliverable: Failed Login Filter (External IP Simulation)

To streamline analysis, I developed an XML query to isolate failed authentication attempts originating from external network sources.
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4625)]]</Select>
  </Query>
</QueryList>
```

![ac540f9e13d697361af178e5cf2d8572.png](:/c6f928a3dcde4b459dc23886b5ec9ed8)

* * *

## Week 6: Detecting Unmanaged PowerShell/C# Injection

**Objective:** Leverage advanced ETW providers to detect malicious .NET assembly loading and process injection that bypasses standard process auditing.

### Advanced Telemetry vs. Native Auditing

Standard process auditing (Event ID 4688) often fails to capture "living off the land" attacks where PowerShell or C# code is executed within the memory of a non-PowerShell process (unmanaged injection). To gain visibility, I focused on specialized **Event Tracing for Windows (ETW)** providers.

### Strategic Providers Utilized:

* 
**Microsoft-Windows-DotNETRuntime:** Ideal for identifying anomalies in .NET application execution and potential malicious .NET assembly loading.


* 
**Microsoft-Windows-Kernel-Process:** Used to detect unusual process behaviors such as process injection and process hollowing.


* 
**Microsoft-Windows-CodeIntegrity:** Monitored to identify attempts to load unsigned or malicious code/drivers.



### Lab Activity: Injection Detection

In my sandbox, I simulated a tool loading the .NET runtime into a native process to execute C# code without launching `powershell.exe`.

* **Finding:** By monitoring the `DotNETRuntime` provider, I could see the JIT (Just-In-Time) compilation and assembly loading events within a process that should not normally be running .NET code.

* To showcase unmanaged PowerShell injection, we can inject an unmanaged PowerShell-like DLL into a random process, such as spoolsv.exe. We can do that by utilizing the PSInject project in the following manner.
### Spoolsv ID=2400
  ![4f244c6f6b1d6b753f560e58ed64def4.png](:/8e9dbbee164840759ce40c7ff322a2d0)
  ### After Injection
![328a01346e4dd5c8b11d0f0a4156a4fd.png](:/b06a40ad29c049609d5fbc6755e53489)

![6e219da25965f854d7b3af906295dd93.png](:/c496ed426bbc401bb355270958f4b28f)

```
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\Users\techadmin\Downloads\logs\etw.json
```

* * *

## Week 7: Active Directory & Kerberos

**Objective:** Understand the identity architecture of enterprise environments and the vulnerabilities within the Kerberos protocol.

### Explaining Service Principal Names (SPNs)

A **Service Principal Name (SPN)**  : An instance of a service is uniquely identified by its Service Principal Name (SPN). SPNs link a service (such as HTTP or MSSQL) to a particular service account in the directory in an Active Directory setting. An adversary requests a service ticket for an SPN linked to a user account during a Kerberoasting attack. Since the ticket is encrypted with the password hash of that account, the attacker can try to crack it offline in order to retrieve the plaintext password.

* * *

## Week 8: Month 2 Capstone - Credential Dumping

**Objective:** Use the **Atomic Red Team** framework to simulate a real-world attack and validate logging coverage.

### Challenge: T1003 (Credential Dumping)

I executed a simulated credential dump (T1003) on a test VM. This technique targets the Local Security Authority Subsystem Service (LSASS) to harvest passwords or hashes.
#### Tools: mimikatz (Credential Dumping tool)
![f7b20f5eab93c30c6b8ba463e6019d49.png](:/7a70e23fbf18426294decc97d358fada)

### Detection Results
![3517f9ab8d10ed36759ee2ffc817dfb7.png](:/660ee8a736d248a791559a255a2268bc)

![a90f5841e4ee9ac43fbe80ac0a1651d2.png](:/48d0c115cd5746aea83bb4eb5f1710bd)

```powershell
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=10} | Where-Object { $_.Message -match "mimikatz.exe" -and $_.Message -match "lsass.exe" } | Format-List *
```

* * *
## More Examples 
### Detecting DLL Hijacking
* Vulnerable App: calc.exe
* DLL: WININET.dll
* Tools: Stephen Fewer's "hello world" reflective DLL [ https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin ]
* Rename `reflective_dll.x64.dll` to `WININET.dll`
* Copy calc.exe to Desktop (any user controlled dir) same as the compromised DLL
![3db1a4ab9eb1b118a3ba608920cb9423.png](:/47e82d405b4e420aaf60d50a2a311a46)

### Detection Results
![5aaa12db685d3ed4119fd5df0f4bc74b.png](:/5486d3e49b06453f8bb773aa436db71b)
```powershell
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=7} | Where-Object { $_.Message -match "calc.exe" -and $_.Message -match "WININET.dll" } | Format-List *
```
![fbf836000090f1d54a4c3791b45eb556.png](:/f7d8d0329bdb4738a6f7db8eba1731dd)
## Self-Assessment & Reflection

- **Environment:** All labs were conducted in a controlled sandbox environment on a local workstation to ensure safety and repeatability.
    
- **Skill Acquisition:** I have moved beyond just identifying Event IDs; I can now correlate different logs (using Logon IDs) to reconstruct an attacker's timeline.
    
- **Areas for Growth:** I plan to further explore the **Windows Filtering Platform (ID 5157)** to better understand how to detect malicious C2 traffic at the kernel level.

## Resoures

* Auditing settings on object were changed. - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4907
* Sysmon Information/ IDs etc - https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
* Sysmon-Config - https://github.com/SwiftOnSecurity/sysmon-config || https://github.com/SwiftOnSecurity/sysmon-config
* Hijacking DLLs Blog Post - https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows
* Reflective DLLInjection - https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin
* ProcessHacker - https://systeminformer.sourceforge.io/
* PSInject - https://github.com/EmpireProject/PSInject
* Mimikatz - https://github.com/gentilkiwi/mimikatz
* LSASS - https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service
* SilkETW - https://github.com/mandiant/SilkETW
* Get-WinEvent - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5&viewFallbackFrom=powershell-7.3
* https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf
* https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw
