# Custom Velociraptor Artifacts for use.

### Custom.Server.Monitor.Autolabeling.Clients.yaml
Checks for already set labels, which deletes, and assign automatically Domain Role, Username, IP Address and Domain labels.

### Custom.Windows.Detection.NamedPipes.CobaltStrike
Search for any process handles that match known CobaltStrike named pipe patterns. Credits to @svch0st, https://gist.github.com/svch0stz

### Custom.Windows.Scan.YaraTool
This artifact deploys the classic Yara scanner and presents all files detected grouped by rule matched.

### Custom.Windows.Sysinternals.SysmonInstall
This artifact is modified so that you include the old Sysmon binary in order to uninstall current Sysmon version,
copies the files into C:\Windows and installs sysmon, provided the new sysmon binary or configuration are different.

### Custom.Windows.System.Pslist
A custom version updated to also show the child processes of each process.

### Generic.Remediation.Process
This artifact enables killing a process by Name, Path, PID or Hash, both in Windows and Linux.

### Server.Enrichment.AbuseIPDB
Queries AbuseIPDB by api to see ip address reputation.

### Server.Windows.Scan.CobaltStrikeParserMaster
Works in a Windows Velociraptor Server and uses CobaltStrikeParser-master (https://github.com/Sentinel-One/CobaltStrikeParser)
to parse a url, ip address with port or a file which is uploaded on the server.

### Server.Linux.Scan.CobaltStrikeParserMaster
Works in a Linux Velociraptor Server and uses CobaltStrikeParser-master (https://github.com/Sentinel-One/CobaltStrikeParser)
to parse a url, ip address with port or a file which is uploaded on the server.

### Windows.Detection.Hollowfind
This artifact checks for hollow processes with the following methology:
    
1.Creates a list of processes using pslist plugin
2.For each process, it retrieves information from the process structure, PEB and the VAD that is pointed by PEB.ImageBaseAddress and checks whether there is an executable in the processes’ s VADs.
3.Detects whether the process is hollowed. The criteria used are:
    ▪ VAD’s Protection equals to PAGE_EXECUTE_READWRITE or
    ▪ There is no VAD entry corresponding to PEB.ImageBaseAddress or
    ▪ There is an executable in processes’ VADs that PEB.ImageBaseAddress does not point to and has PAGE_EXECUTE_WRITECOPY protection.

### Custom.Windows.Scan.CrowdResponse
This artifact deploys CrowdResponse for yara scanning. The configuration file must either be uploaded or entered in the appropriate field.

### Custom.Windows.Scan.LokiEnriched
Upgraded VQL artifact of Loki Scanner. You have to include the signature-base folder inside the loki.zip\loki folder and rename the executable to "loki.exe"

### Custom.Artifact.Windows.Search.AlienVault
Downloads a .csv file from AlienVault and hunts the endpoint.
Works with Custom.Windows.System.DNSCache in order to look effectively in the reversed ".in-addr.arpa" entries.
