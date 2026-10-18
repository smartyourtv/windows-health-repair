"""Recorded/mocked Windows command outputs used by the unit tests.

These mirror the real formats (SFC/DISM console text, PowerShell
ConvertTo-Json) closely enough to exercise the parsers honestly.
"""

SFC_CLEAN = """
Verification 100% complete.

Windows Resource Protection did not find any integrity violations.
"""

SFC_VIOLATIONS = """
Verification 100% complete.

Windows Resource Protection found corrupt files but was unable to fix
some of them.
"""

SFC_REPAIRED = """
Verification 100% complete.

Windows Resource Protection found corrupt files and successfully
repaired them.
"""

DISM_HEALTHY = """
Deployment Image Servicing and Management tool
Version: 10.0.22621.2792

Image Version: 10.0.22631.2861

No component store corruption detected.
The operation completed successfully.
"""

DISM_REPAIRABLE_SCAN = """
Deployment Image Servicing and Management tool
Version: 10.0.22621.2792

Image Version: 10.0.22631.2861

The component store is repairable.
The operation completed successfully.
"""

DISM_ERROR = """
Error: 0x800f081f

The source files could not be found.
"""

PHYSICAL_DISKS_JSON = (
    '[{"FriendlyName":"Samsung SSD 970 EVO Plus 1TB",'
    '"MediaType":"SSD","HealthStatus":"Healthy",'
    '"OperationalStatus":"OK","Size":1000204886016},'
    '{"FriendlyName":"WDC WD40EZRZ","MediaType":"HDD",'
    '"HealthStatus":"Warning","OperationalStatus":"Degraded",'
    '"Size":4000787030016}]'
)

VOLUMES_JSON = (
    '[{"DriveLetter":"C","FileSystemLabel":"Windows",'
    '"Size":214748364800,"SizeRemaining":10737418240},'
    '{"DriveLetter":"D","FileSystemLabel":"Data",'
    '"Size":2000000000000,"SizeRemaining":900000000000}]'
)

PNP_PROBLEMS_JSON = (
    '[{"Name":"Unknown USB Device (Device Descriptor Request Failed)",'
    '"PNPClass":"USB","ConfigManagerErrorCode":43},'
    '{"Name":"PCI Simple Communications Controller",'
    '"PNPClass":"","ConfigManagerErrorCode":28},'
    '{"Name":"Fine Device","PNPClass":"Net",'
    '"ConfigManagerErrorCode":0}]'
)

SERVICES_JSON = (
    '[{"Name":"wuauserv","DisplayName":"Windows Update",'
    '"Status":"Stopped","StartType":"Manual"},'
    '{"Name":"bits","DisplayName":"Background Intelligent Transfer '
    'Service","Status":"Running","StartType":"Automatic"},'
    '{"Name":"cryptsvc","DisplayName":"Cryptographic Services",'
    '"Status":"Running","StartType":"Automatic"},'
    '{"Name":"UsoSvc","DisplayName":"Update Orchestrator Service",'
    '"Status":"Stopped","StartType":"Disabled"}]'
)

PENDING_REBOOT_JSON = '{"cbs":true,"wu":false,"file_rename":true,' \
                      '"computer_rename":false}'

EVENTS_JSON = (
    '[{"ProviderName":"Microsoft-Windows-Kernel-Power","Id":41,'
    '"LevelDisplayName":"Critical"},'
    '{"ProviderName":"Microsoft-Windows-Kernel-Power","Id":41,'
    '"LevelDisplayName":"Critical"},'
    '{"ProviderName":"disk","Id":7,"LevelDisplayName":"Error"},'
    '{"ProviderName":"Microsoft-Windows-DistributedCOM","Id":10016,'
    '"LevelDisplayName":"Error"},'
    '{"ProviderName":"Mystery-Provider","Id":4242,'
    '"LevelDisplayName":"Error"}]'
)

DEFENDER_STATUS_JSON = (
    '{"AMServiceEnabled":true,"AMRunningMode":"Normal",'
    '"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,'
    '"IoavProtectionEnabled":true,"IsTamperProtected":true,'
    '"AntivirusSignatureLastUpdated":"/Date(1760313600000)/",'
    '"AntivirusSignatureAge":1,'
    '"QuickScanEndTime":"/Date(1760227200000)/",'
    '"FullScanEndTime":null,"QuickScanNeeded":false,'
    '"FullScanNeeded":false}'
)

DEFENDER_STATUS_BAD_JSON = (
    '{"AMServiceEnabled":true,"AntivirusEnabled":true,'
    '"RealTimeProtectionEnabled":false,'
    '"IsTamperProtected":false,'
    '"AntivirusSignatureAge":12,'
    '"QuickScanEndTime":null,"QuickScanNeeded":true}'
)

DEFENDER_EXCLUSIONS_JSON = (
    '{"ExclusionPath":["C:\\\\Games","D:\\\\Downloads\\\\crack"],'
    '"ExclusionExtension":[".tmp"],"ExclusionProcess":[],'
    '"ExclusionIpAddress":null}'
)

FIREWALL_JSON = (
    '[{"Name":"Domain","Enabled":true},'
    '{"Name":"Private","Enabled":true},'
    '{"Name":"Public","Enabled":false}]'
)

THREATS_JSON = (
    '[{"ThreatID":2147735505,'
    '"InitialDetectionTime":"/Date(1760313600000)/",'
    '"ThreatStatusID":3,"Resources":["file:_C:\\\\x\\\\bad.exe"]}]'
)

RESTORE_POINTS_JSON = (
    '[{"Created":"20261015093000.000000-420",'
    '"Description":"Windows Update"},'
    '{"Created":"20261014120000.000000-420",'
    '"Description":"Manual"}]'
)


# --- driver inventory / WU driver search / install (feature pack) ------
SIGNED_DRIVERS_JSON = (
    '[{"DeviceName": "NVIDIA GeForce GTX 1660 Ti", '
    '"DriverProviderName": "NVIDIA", "DriverVersion": "32.0.15.6094", '
    '"DriverDate": "2024-08-14T00:00:00", "InfName": "oem42.inf", '
    '"DeviceID": "PCI\\\\VEN_10DE", "DeviceClass": "Display"}, '
    '{"DeviceName": "Realtek Audio", "DriverProviderName": '
    '"Realtek Semiconductor Corp.", "DriverVersion": "6.0.9700.1", '
    '"DriverDate": "2024-05-01T00:00:00", "InfName": "oem7.inf", '
    '"DeviceID": "HDAUDIO\\\\X", "DeviceClass": "MEDIA"}, '
    '{"DeviceName": "Standard SATA AHCI Controller", '
    '"DriverProviderName": "Microsoft", "DriverVersion": '
    '"10.0.26100.1", "DriverDate": "2006-06-21T00:00:00", '
    '"InfName": "mshdc.inf", "DeviceID": "PCI\\\\VEN_8086", '
    '"DeviceClass": "HDC"}]')

WU_DRIVER_SEARCH_JSON = (
    '[{"Title": "NVIDIA - Display - 32.0.15.7000", "UpdateID": '
    '"aaaaaaaa-1111-2222-3333-444444444444", "RevisionNumber": 200, '
    '"DriverClass": "Display", "DriverManufacturer": "NVIDIA", '
    '"DriverModel": "NVIDIA GeForce GTX 1660 Ti", '
    '"MaxDownloadSize": 650117120, '
    '"LastDeploymentChangeTime": "2026-09-01"}, '
    '{"Title": "Realtek - MEDIA - 6.0.9800.1", "UpdateID": '
    '"bbbbbbbb-1111-2222-3333-444444444444", "RevisionNumber": 100, '
    '"DriverClass": "MEDIA", "DriverManufacturer": "Realtek", '
    '"DriverModel": "Realtek Audio", "MaxDownloadSize": 45000000, '
    '"LastDeploymentChangeTime": "2026-08-15"}]')

WU_INSTALL_OK_JSON = '{"ResultCode": 2, "RebootRequired": false}'
WU_INSTALL_REBOOT_JSON = '{"ResultCode": 2, "RebootRequired": true}'
WU_INSTALL_FAILED_JSON = '{"ResultCode": 4, "RebootRequired": false}'
WU_INSTALL_NOTFOUND_JSON = '{"NotFound": true}'

# --- boot-time report -----------------------------------------------------
BOOT_EVENTS_JSON = (
    '[{"Id": 100, "Time": "2026-10-15T07:59:00", "BootTime": '
    '"48000", "Name": null, "TotalTime": null, '
    '"DegradationTime": null}, '
    '{"Id": 101, "Time": "2026-10-15T07:59:20", "BootTime": null, '
    '"Name": "C:\\\\Program Files\\\\SlowSuite\\\\slow.exe", '
    '"TotalTime": "9200", "DegradationTime": "1500"}, '
    '{"Id": 102, "Time": "2026-10-15T07:59:25", "BootTime": null, '
    '"Name": "SomeService", "TotalTime": "3100", '
    '"DegradationTime": "0"}, '
    '{"Id": 100, "Time": "2026-10-08T08:01:00", "BootTime": '
    '"61000", "Name": null, "TotalTime": null, '
    '"DegradationTime": null}]')

# --- v1.1.0: security restructure / troubleshooter / preventative --------
DEFENDER_STATUS_NOISY = (
    "Preparing modules for first use.\r\n"
    '{"AMServiceEnabled":true,"AMRunningMode":"Normal",'
    '"AntivirusEnabled":true,"RealTimeProtectionEnabled":true,'
    '"IoavProtectionEnabled":true,"IsTamperProtected":true,'
    '"AntivirusSignatureVersion":"1.453.123.0",'
    '"AntivirusSignatureAge":0,'
    '"QuickScanEndTime":"/Date(1760313600000)/",'
    '"FullScanEndTime":null,"QuickScanNeeded":false,'
    '"FullScanNeeded":false}\r\n')

NSLOOKUP_OK = (
    "Server:  router.local\r\nAddress:  192.168.1.1\r\n\r\n"
    "Non-authoritative answer:\r\nName:    www.microsoft.com\r\n"
    "Address:  20.236.44.162\r\n")

NSLOOKUP_FAIL = "*** router.local can't find www.microsoft.com: " \
                "Server failed\r\n"

PING_OK = (
    "Pinging 192.168.1.1 with 32 bytes of data:\r\n"
    "Reply from 192.168.1.1: bytes=32 time=1ms TTL=64\r\n"
    "Reply from 192.168.1.1: bytes=32 time=1ms TTL=64\r\n\r\n"
    "Ping statistics for 192.168.1.1:\r\n"
    "    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\n")

PING_FAIL = (
    "Pinging 192.168.1.1 with 32 bytes of data:\r\n"
    "Request timed out.\r\nRequest timed out.\r\n\r\n"
    "Ping statistics for 192.168.1.1:\r\n"
    "    Packets: Sent = 2, Received = 0, Lost = 2 (100% loss),\r\n")

NET_ADAPTERS_JSON = (
    '[{"Name":"Wi-Fi","Status":"Up","LinkSpeed":"866 Mbps",'
    '"InterfaceDescription":"Intel Wireless-AC 9560"},'
    '{"Name":"Ethernet","Status":"Disconnected","LinkSpeed":"0 bps",'
    '"InterfaceDescription":"Realtek GbE"}]')

SOUND_DEVICES_JSON = (
    '[{"Name":"Realtek High Definition Audio","Status":"OK"}]')

SMART_PREDICT_JSON = (
    '[{"InstanceName":"SCSI\\\\Disk&Ven_NVMe\\\\0",'
    '"PredictFailure":false},'
    '{"InstanceName":"SCSI\\\\Disk&Ven_WDC\\\\1",'
    '"PredictFailure":true}]')

WU_PENDING_JSON = '{"Count": 5}'

BUGCHECK_EVENTS = [
    {"ProviderName": "Microsoft-Windows-WER-SystemErrorReporting",
     "Id": 1001, "LevelDisplayName": "Error",
     "Message": "The computer has rebooted from a bugcheck. The "
                "bugcheck was: 0x000000d1 (0x0000000000000028)."},
    {"ProviderName": "Microsoft-Windows-WER-SystemErrorReporting",
     "Id": 1001, "LevelDisplayName": "Error",
     "Message": "The computer has rebooted from a bugcheck. The "
                "bugcheck was: 0x000000d1 (0x0000000000000028)."},
]

WU_FAIL_EVENTS = [
    {"ProviderName": "Microsoft-Windows-WindowsUpdateClient",
     "Id": 20, "LevelDisplayName": "Error",
     "Message": "Installation Failure: Windows failed to install "
                "the following update with error 0x80070422: "
                "Feature update."},
    {"ProviderName": "Microsoft-Windows-WindowsUpdateClient",
     "Id": 31, "LevelDisplayName": "Error",
     "Message": "Windows Update failed to download an update."},
]

# --- installed programs ----------------------------------------------------
PROGRAMS_JSON = (
    '[{"DisplayName": "Useful App", "DisplayVersion": "3.2", '
    '"Publisher": "Useful Co", "InstallDate": "20260301", '
    '"EstimatedSize": 204800, "InstallLocation": "C:\\\\Useful"}, '
    '{"DisplayName": "Ask Toolbar", "DisplayVersion": "1.0", '
    '"Publisher": "APN", "InstallDate": "", "EstimatedSize": 2048, '
    '"InstallLocation": ""}, '
    '{"DisplayName": "Photo Suite Trial", "DisplayVersion": "9", '
    '"Publisher": "PhotoCo", "InstallDate": "20250101", '
    '"EstimatedSize": 512000, "InstallLocation": "C:\\\\Photo"}, '
    '{"DisplayName": "Useful App", "DisplayVersion": "3.2", '
    '"Publisher": "Useful Co", "InstallDate": "20260301", '
    '"EstimatedSize": 204800, "InstallLocation": "C:\\\\Useful"}, '
    '{"DisplayName": "Alpha Updater", "DisplayVersion": "1", '
    '"Publisher": "A", "InstallDate": "", "EstimatedSize": 100, '
    '"InstallLocation": ""}, '
    '{"DisplayName": "Beta Updater", "DisplayVersion": "1", '
    '"Publisher": "B", "InstallDate": "", "EstimatedSize": 100, '
    '"InstallLocation": ""}, '
    '{"DisplayName": "Gamma Update Helper", "DisplayVersion": "1", '
    '"Publisher": "G", "InstallDate": "", "EstimatedSize": 100, '
    '"InstallLocation": ""}]')
