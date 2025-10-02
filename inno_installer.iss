; inno_installer.iss — per build ONEFILE

[Setup]
AppName=STB_PRO
AppVersion=1.0.8
DefaultDirName={autopf}\STB_PRO
DefaultGroupName=STB_PRO
OutputBaseFilename=STB_PRO-Setup
OutputDir={#SourcePath}\Output
SetupIconFile=stbpro.ico
ArchitecturesInstallIn64BitMode=x64
Compression=lzma
SolidCompression=yes

[Files]
; con --onefile esiste SOLO il .exe, non la cartella STB_PRO\
Source: "{#SourcePath}\dist\STB_PRO.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\STB_PRO"; Filename: "{app}\STB_PRO.exe"; WorkingDir: "{app}"
Name: "{commondesktop}\STB_PRO"; Filename: "{app}\STB_PRO.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Crea icona sul desktop"; GroupDescription: "Icone:"
