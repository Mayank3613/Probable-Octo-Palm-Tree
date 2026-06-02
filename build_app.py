import os
import platform
import PyInstaller.__main__

def build():
    print(f"Building OctoPlamTree for {platform.system()}...")
    
    separator = ';' if platform.system() == 'Windows' else ':'
    
    args = [
        'app_tray.py',
        '--name=OctoPlamTree',
        '--noconfirm',
        '--windowed', # No console window
        '--icon=logo.ico',
        '--clean',
        f'--add-data=logo.png{separator}.',
        f'--add-data=backend-api{separator}backend-api',
        f'--add-data=ai-engine{separator}ai-engine',
        f'--add-data=local-agent{separator}local-agent',
        f'--add-data=dashboard/dist{separator}dashboard/dist',
        f'--add-data=ai-engine/model.joblib{separator}ai-engine',
        '--hidden-import=uvicorn',
        '--hidden-import=fastapi',
        '--hidden-import=sklearn.ensemble._forest',
        '--hidden-import=scapy',
        '--hidden-import=psutil',
        '--hidden-import=geoip2',
        '--hidden-import=ipwhois',
        '--hidden-import=watchdog',
        '--hidden-import=pystray',
        '--hidden-import=PIL',
        '--hidden-import=aiosqlite',
    ]
    
    PyInstaller.__main__.run(args)
    
    print("\n" + "="*50)
    print("BUILD COMPLETE")
    print("="*50)
    print(f"Your executable is located in the 'dist' folder.")
    if platform.system() == 'Windows':
        print(f"You can wrap 'dist/OctoPlamTree/OctoPlamTree.exe' in an installer using Inno Setup or NSIS.")
    elif platform.system() == 'Darwin':
        print(f"You can distribute 'dist/OctoPlamTree.app' as a DMG or zipped app.")
    else:
        print(f"You can distribute 'dist/OctoPlamTree' as a portable package.")

if __name__ == "__main__":
    build()
