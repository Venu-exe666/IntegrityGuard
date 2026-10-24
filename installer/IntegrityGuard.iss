; IntegrityGuard v2.0 per-user Windows installer.
; Compile from the repository root with:
;   & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" ".\installer\IntegrityGuard.iss"

#define MyAppName "IntegrityGuard"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Venu-exe666"
#define MyAppExeName "IntegrityGuard.exe"
#define MyAppSourceDir "..\dist\IntegrityGuard"

[Setup]
; Keep this AppId unchanged in future releases so upgrades use the same app identity.
AppId={{FAB42CBE-D907-45ED-97C3-640C6DD6D7D1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppCopyright=Copyright (c) 2026 Venu-exe666
DefaultDirName={localappdata}\Programs\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
OutputDir=..\dist\installer
OutputBaseFilename=IntegrityGuard-Setup-v2.0.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=110
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
Uninstallable=yes
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UsePreviousAppDir=yes
DirExistsWarning=no
VersionInfoVersion=2.0.0.0
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}
VersionInfoDescription={#MyAppName} Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Package the complete PyInstaller onedir tree, including _internal.
Source: "{#MyAppSourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

; GUI baselines live under {localappdata}\IntegrityGuard\baselines, outside
; {app}. This installer intentionally has no [Dirs], [InstallDelete], or
; [UninstallDelete] entries for that data location, so installation, upgrades,
; and uninstallation leave user baselines and scan data untouched.
