; OctoPlamTree Windows Installer Script
; Requires NSIS (Nullsoft Scriptable Install System)

!define APPNAME "OctoPlamTree"
!define APPVERSION "1.0.0"
!define APPDIR "dist\OctoPlamTree"
!define INSTALLDIR "$PROGRAMFILES64\OctoPlamTree"

Name "${APPNAME} ${APPVERSION}"
OutFile "OctoPlamTree_Setup_Windows.exe"
InstallDir "${INSTALLDIR}"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  
  ; Copy all files from the PyInstaller dist folder
  File /r "${APPDIR}\*"
  
  ; Create Start Menu shortcut
  CreateShortcut "$SMPROGRAMS\${APPNAME}.lnk" "$INSTDIR\OctoPlamTree.exe"
  
  ; Create Desktop shortcut
  CreateShortcut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\OctoPlamTree.exe"
  
  ; Write uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
  
  ; Register uninstall in control panel
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${APPNAME}.lnk"
  Delete "$DESKTOP\${APPNAME}.lnk"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
SectionEnd
