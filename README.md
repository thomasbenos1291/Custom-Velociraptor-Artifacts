# Custom Velociraptor Artifacts for use.

### Custom.Server.Monitor.Autolabeling.Clients.yaml
Checks for already set labels, which deletes, and assign automatically Domain Role, Username, IP Address and Domain labels.

### Custom.Windows.Detection.NamedPipes.CobaltStrike
Search for any process handles that match known CobaltStrike named pipe patterns. Credits to @svch0st, https://gist.github.com/svch0stz

### Custom.Windows.Scan.YaraTool
This artifact deploys the classic Yara scanner and presents all files detected grouped by rule matched.

### Custom.Windows.System.Pslist
A custom version updated to also show the child processes of each process.

### Custom.Windows.Linux.Pslist
A custom version updated to also show the child processes of each linux process.

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

### Custom.Windows.Scan.YaraTool
This artifact deploys the classic Yara scanner tool in Windows. Can scan both processes and a given target directory.

### Custom.Windows.Scan.CrowdResponse
This artifact deploys CrowdResponse for yara scanning. The configuration file must either be uploaded or entered in the appropriate field.

### Custom.Windows.Scan.LokiEnriched
Upgraded VQL artifact of Loki Scanner.

### Custom.Generic.Scanner.ThorZIP.yaml
Customised version of the original VQL artifact of THOR scanner that also parses the .json that is produced.

### Custom.Artifact.Windows.Search.AlienVault
Downloads a .csv file from AlienVault and hunts the endpoint.
Works with Custom.Windows.System.DNSCache in order to look effectively in the reversed ".in-addr.arpa" entries.

### Windows.UploadAuditPolicy
Uploads an Audit Policy in .csv format to a Windows endpoint.

### Custom.Server.RunCustomInfo
Run client interrogation on clients and delete other interrogation flows.

### Custom.Server.Monitoring.ScheduleCustomInfo
Run client interrogation periodically with Custom.Server.RunCustomInfo in order to also remove previous interrogation data.

### Custom.Windows.EventLogs.ScriptBlockHunter
Hunt for the Windows ScriptBlock event log 4104 and concatenate all events by ScriptBlock Id to produce the whole script.

### Custom.Windows.EventLogs.HayabusaNew
Customised version of Hayabusa that utilizes an installation artifact in order for the hayabusa binary to be always inside the Tools directory of Velociraptor.

### Custom.Windows.EventLogs.HayabusaMonitor
Monitoring artifact that executes Hayabusa every 2 minutes (by default) for events that happened 2 minutes ago (by default) in order to have near-real-time monitoring.

### Custom.Windows.Sysinternals.Autoruns
Customised version of the original VQL artifact that also utilizes VirusTotal query from the endpoint.

### Custom.Windows.Sysinternals.Sigcheck
Deploys Sysninternals Sigcheck and also can utilize VirusTotal query from the endpoint.

### Custom.Server.Monitoring.ScheduleAllFlowDeletion
Custom artifact that schedules the deletion of all flows in a certain time period to make up space in the datastore.

### Custom.Windows.Detection.ISOMount
Customized version of the original artifact in order to use VSSAnalysisAge instead of SearchVSS parameter due to update of the Windows.EventLogs.EvtxHunter artifact.
