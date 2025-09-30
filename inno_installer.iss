; inno_installer.iss
#define MyAppName "STB_PRO"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Org"
#define MyAppExeName "STB_PRO.exe"

[Setup]
AppId={{A1B2C3D4-1111-2222-3333-444455556666}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={commonpf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.
OutputBaseFilename=STB_PRO-Setup
Compression=lzma
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
SetupIconFile=stbpro.ico

[Files]
; Copia il contenuto della cartella build PyInstaller onedir:
Source: "dist\STB_PRO\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Crea un'icona sul Desktop"; GroupDescription: "Opzioni aggiuntive:"; Flags: unchecked