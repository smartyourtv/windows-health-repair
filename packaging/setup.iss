; =====================================================================
; Generic Inno Setup script for Muse-built Windows apps (REUSABLE).
;
; Per-user installer: NO admin rights needed to install, NO Python
; requirement. Installs one PyInstaller-built exe into
;   {localappdata}\Programs\<InstallFolder>
; creates a Start Menu shortcut (+ optional Desktop shortcut), and
; registers a standard uninstaller (Settings > Apps).
;
; Every per-app value is an Inno preprocessor define with a default
; for THIS app below. The build script / CI passes /D defines read
; from packaging\app-config.json, e.g.:
;   ISCC /DMyAppName="Other App" /DMyExeName="Other.exe" setup.iss
; See TEMPLATE-NOTES.md before reusing: each app MUST get its own
; MyAppId GUID (that is the uninstall identity in Windows).
; =====================================================================

#ifndef MyAppId
  #define MyAppId "DAD27740-5D41-490B-8A4F-67261960D5A1"
#endif
#ifndef MyAppName
  #define MyAppName "Windows Health & Repair"
#endif
#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif
#ifndef MyAppPublisher
  #define MyAppPublisher "smartyourtv"
#endif
#ifndef MyExeName
  #define MyExeName "WindowsHealthRepair.exe"
#endif
#ifndef MyInstallFolder
  #define MyInstallFolder "WindowsHealthRepair"
#endif
#ifndef MySetupBaseName
  #define MySetupBaseName "WindowsHealthRepair-Setup"
#endif
; Path to the PyInstaller output. Default assumes this .iss lives in
; packaging\ and PyInstaller wrote to <repo root>\dist\.
#ifndef MySourceExe
  #define MySourceExe "..\dist\" + MyExeName
#endif
#ifndef MyOutputDir
  #define MyOutputDir "..\dist"
#endif

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; Per-user install: lowest privileges, no admin prompt to install.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=no
DefaultDirName={localappdata}\Programs\{#MyInstallFolder}
; Single program, single shortcut set - skip the group-name page so
; the wizard stays Next / Install / Finish simple.
DisableProgramGroupPage=yes
DefaultGroupName={#MyAppName}
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\{#MyExeName}
OutputDir={#MyOutputDir}
OutputBaseFilename={#MySetupBaseName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Unsigned for now: Windows SmartScreen will warn on first run
; ("More info" -> "Run anyway"). Documented in the README.

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
Source: "{#MySourceExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyExeName}"; Description: "Launch {#MyAppName} now"; Flags: nowait postinstall skipifsilent
