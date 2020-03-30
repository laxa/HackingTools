# This is a simple list of all tools that can be related to hacking, there are windows and linux tools

This repo was created by [Geluchat](https://github.com/Geluchat) and [laxa](https://github.com/Laxa)
The overall idea is to find quickly a tool that could suit your need or help you in any way related to computer hacking.
This list is supposed to be as exhaustive as possible.

All tools are listed like this \[TAG1|\[TAG2|TAG3...]][Clickable name](#): Short description

### Legend

* \[G]: Github/Git repository # Note, this flag automatically implies the \[O] flag
* \[S]: Software (Imply that it's not always 100% free and that it's not open source or restrictive license)
* \[F]: Freeware (Free software, doesn't necessarily means that it's opensource)
* \[I]: Website
* \[P]: Plugin for chrome
* \[R]: Plugin for firefox
* \[D]: Plugin for IDA Pro
* \[C]: CLI tool
* \[O]: Open source
* \[M]: Misceallenous
* \[L]: Reverse Flag: is set only when Linux compatible
* \[W]: Reverse Flag: is set only when Windows compatible

### Binary

* \[I] https://malwr.com/: online binary analysis (behaviour analysis in sandbox)
* \[I] https://www.virustotal.com/: online binary analysis by AV
* \[I] https://www.hybrid-analysis.com: online binary analysis (behaviour analysis in sandbox)
* \[I] https://retdec.com/: online decompiler for c/c++ binaries
* \[I] http://www.showmycode.com/: online decompiler for .NET/flash and others...
* \[I] http://www.javadecompilers.com/: java decompiler online
* \[I] https://defuse.ca/online-x86-assembler.htm: online frontend for disassembling/assembling x86/x86_64
* \[S|W] [Reflector]: assembly browser for .NET
* \[F|O|W] [Simple Assembly Explorer]: another .NET disassembler
* \[F|O|W] [de4dot]: .NET deobfuscator
* \[G|W] [dnSpy]: .NET decompiler, debugger, assembly editor and more
* \[S] [IDA]: debugger / disassembler, most complete tool for static/dynamic binary analysis
* \[D] [FindCrypt2]: Detect static code for known algorithms
* \[D|G] [ScyllaHide]: Anti-Anti debug
* \[D|G] [DIE]: Dynamic IDA Enrichment
* \[F|O] [OllyDbg]: debugger
* \[F|O|W] [x64dbg]: debugger
* \[F|W] [Detect it easy]: binary packer detection
* \[S|W] [apimonitor]: inspect process calls and trace them
* \[S|W] [processmonitor]: Microsoft tool to quickly see system calls
* \[F|W] [PEiD]: identify which packer has been used on PE binaries
* \[O|W] [XNResourceEditor]: Browse resources in PE
* \[F|W] [ImpREC]: reconstruct IAT table for unpacked binaries
* \[O|W] [cheatengine]: memory scanner and other usefull things
* \[C|O|L] [gdb]: Gnu debugger for linux
* \[M|G] [peda]: python plugin for gdb
* \[M|G] [gef]: gdb plugin supporting more architectures than peda
* \[C|O|L] [strace/ltrace]: system call tracers / dynamic call tracers (librairies)
* \[S] [dede]: delphi decompiler
* \[S] [Pin]: dynamic binary instrumentation framework
* \[G] [Pintool]: binary password finder for ctf using pin
* \[O|L] [checksec]: check binary protections
* \[G] [Qira]: timeless debugger with web interface by geohot
* \[G|C] [ROPGadget]: tool for rop chaining
* \[G|C] [plasma]: interactive disassembler in pseudo-C with colored syntax
* \[O|C|L] [XOCopy]: copy memory of execute only ELF binaries
* \[G|C] [Shellsploit]: shellcode generator framework
* \[G|C] [radare2]: analyzer, disassembler, debugger
* \[G] [Bokken]: Python-GTK GUI for radare2
* \[G|C] [libformatstr]: python lib to make string format exploits
* \[G] [pwntools]: Python framework to quickly develop exploits
* \[G] [binjitsu]: fork of pwntools
* \[G|C] [fixenv]: Script to align stack withtout ASLR and gdb,strace,ltrace
* \[G] [Voltron]: Great UI Debugger
* \[G] [Z3]: Z3 is a theorem prover
* \[G] [angr]: binary analysis, allows value-set analysis
* \[G] [manticore]: dynamic analysis, symbolic execution framework
* \[G] [rop-tool]: another helpful tool for ROP
* \[G] [villoc]: visualize heap chunks on linux
* \[O|C] [valgrind]: binary analysis allowing to spot read/write errors on memory operations
* \[O|C] [Flawfinder]: static source code analyzer for C/C++ which report possible security weakness
* \[G|C] [afl]: American Fuzy Lop is a fuzzer using dumb/instrumented/qemu
* \[G] [gdbgui]: web lightweight gui interface for gdb
* \[G|C] [one_gadget]: script to find and identify constraints on magc gadget
* \[G|C] [Ropper]: gadgets finder, better than ROPgadget for ARM
* \[G|C] [frida]: Dynamic instrumentation toolkit for most common platforms

### Android/IOS

* \[G] [dex2jar]: apk unpacker (android package)
* \[G|C] [objection]: mobile exploration toolkit, wrapper of frida
* \[G|C] [apktool]: unpack apk, repack them and various other operations
* \[G|C] [uber-apk-signer]: signing apk

### Forensic

* \[C|O] [volatility]: forensic tool to analyse memory dump from windows/linux
* \[C|O] [Autopsy/Sleuth]: analyse hard drives and smartphones
* \[C|O] [Foremost]: file recovery after deletion or format
* \[G|C] [BinWalk]: find files into file
* \[S] [dff]: complete forensic gui analyser with lots of automation
* \[G|C] [origami]: pdf forensic analysis with optional GUI
* \[F|W] [MFTDump]: dump/copy $MFT file on windows
* \[G|C] [AppCompatCacheParser]: dump shimcache entries from Registry (can use offline registry)
* \[F|W] [RegistryExplorer]: GUI to explore registry with search options and possibility to use offline register
* \[S|W] [Agent Ransack]: GUI to search for files/content on shares/local drives

### Cryptography

* \[C|G] [xortool]: find xor key/key length from xor text/binary
* \[C|G] [cribdrag]: interactive crib dragging on xored text
* \[C|G] [hash_extender]: hash extension forger
* \[C|G] [hash-identifier]: hash identifier
* \[C|G] [PadBuster]: break CBC encryption using an oracle
* \[C|G] [lsb-toolkit]: extract bit from images for steganography
* \[C|O] [john]: hash cracker (bruteforce + dico attacks)
* \[F|O] [hashcat]: hash bruteforce cracker that support GPU
* \[C|G] [rsatool]: calculates RSA (p, q, n, d, e) and RSA-CRT (dP, dQ, qInv) parameters given either two primes (p, q) or modulus and private exponent (n, d)
* \[I] http://quipqiup.com/: basic cryptography solver
* \[G|C] [python-paddingoracle]: python tool to exploit padding oracle

### Web

* \[F|O] [DirBuster]: bruteforce/dictionnary attack on webserver to find hidden directories
* \[I] http://pkav.net/XSS2.png: XSS spreadsheet
* \[C|O] [sqlmap]: sql injection
* \[S] [Burp suite]: request tool analysis/forge request
* \[S|W] [fiddler]: HTTP web proxy
* \[I] http://requestb.in/: get a temporary page to receive GET/POST request
* \[I] http://en.42.meup.org/ : Temporary web hosting
* \[I] https://zerobin.net/: anonymous encrypted pastebin
* \[I] http://pastebin.com/: paste code/text with coloration
* \[I] http://portquiz.net/: test outgoing ports
* \[I] http://botscout.com/: check if an IP is flagged as spam/bot
* \[P|R] [HackBar]: xss/sql tests
* \[R] [TamperData]: modify and tamper HTTP requests
* \[R] [Advanced Cookie Manager]: Edit cookie
* \[R] [Modify Headers]: Edit HTTP headers
* \[R] [HTTP Requester]: Edit HTTP requests
* \[R] [FlagFox]: Info about current website
* \[R] [Live HTTP Headers]: View Headers
* \[P] [ModHeader]: edit HTTP requests
* \[G] [Nikto2]: web server scanner
* \[P] [EditThisCookie]: edit cookie, can lock cookie
* \[I] https://dnsdumpster.com/: free domain research tools, find subdomains
* \[I] https://pentest-tools.com/home: subdomain bruteforce not 100% free
* \[G] [Hydra]: remote password cracker
* \[G|C] [wuzz]: webclient curl like using ncurses
* \[G|C] [patator]: web bruteforce/enumator
* \[G|C] [wfuzz]: web bruteforce/enumator
* \[G|C] [teh_s3_bucketeers]: bruteforce s3 buckets
* \[W] https://html5sec.org/: tons of XSS bypass in browsers
* \[G|C] [brakeman]: Ruby on Rails static code analysis security related
* \[G|C] [gixy]: nginx configuration auditor

### Windows

* \[G|C] [impacket]: tons of CLI scripts to interact with windows protocols
* \[G|C] [mimikatz]: Retrieve hash/password, play with DPAPI
* \[G|C] [pypykatz]: python implementation of mimikatz
* \[G|W] [UACME]: Exploits for UAC bypass
* \[G|C] [responder]: Protocol poisoner and rogue server for Microsoft based networks
* \[G|C] [crackmapexec]: Swiss army knife for pentesting
* \[G|C] [lsassy]: lsass dumper and parser
* \[G|C] [dumpert]: lsass memory dumper techniques that can bypass some EDR
* \[G|C] [phys2memprofit]: lsass memory dumper through kernel driver, can bypass EDR
* \[G|C] [pywerview]: partial powersploit's tooling rewritten in python
* \[G|C] [SharpRDP]: can execute commands through RDP connection without any GUI interaction

### Network

* \[C|O] [Netcat]: network tool, can listen or connect using TCP/UDP
* \[C|O] [nmap]: network tool to scan ports and discover services
* \[C|O] [Scapy]: powerful interactive packet manipulation program
* \[C|O] [Aircrack]: wi-fi injection/monitoring/cracking
* \[S|O] [Wireshark]: network packet analyzer
* \[S|W] [NetworkMiner]: sniffer/pcap analyzer, pretty good for files and see what's going on with HTTP traffic
* \[C|O] [Hexinject]: Packer injector and sniffer. Allows to modify packets on the fly
* \[G|C] [ssf]: Client/server socks proxifying and port forwarding with reverse https
* \[G|C] [revsocks]: Go implementation for a socks proxy with reverse SSL/TLS

### Steganography

* \[C|F] [exiftags]: linux package to check jpg tags
* \[O|C] [ExifTool]: read/edit metadata of various file formats
* \[F|O|W] [tweakpng]: tool to resize image for steganography
* \[F|O] [Stegsolve]: perform quick image analysis to find hidden things
* \[F|O] [Wbstego]: retrieve/hide messages in various container

### Misc

* \[F|O|W] [Cuckoo]: interactive sandbox malware analysis
* \[F|O|W] [Photorec]: recover erased file
* \[C|O] [QEMU]: machine emulator and virtualizer
* \[C|S] [metasploit]: Generate payload and browser exploits
* \[C|O] [binutils]: tons of CLI tools
* \[S] [vmware]: virtualization products
* \[I] https://regex101.com/: javascript/python/php regex online
* \[I] http://rubular.com/: ruby regex online
* \[M|O] [kali]: hacking linux OS
* \[I] https://www.exploit-db.com/: exploits database
* \[G|C] [AutoLocalPrivilegeEscalation]: bash script to get root if possible
* \[C|O] [sshpass]: pass ssh password without typing it (highly insecure)
* \[C|O] [virt-what]: simple bash script to detect virtualization environment
* \[W|O] [ProcessHacker]: Extended taskmanager
* \[G] [english-words]: simple english wordlist
* \[G] [fuzzdb]: tons of lists for fuzzing
* \[O|C] [recon-ng]: reconnaissance tool metasploit alike for mails/leaks/contacts/hosts/domains...
* \[G] https://gist.github.com/adamloving/4401361: List of trash/temporary mails list
* \[W] http://www.viewdns.info/: retrieve DNS information, reverse whois, etc...
* \[W] http://packetlife.net/library/cheat-sheets/: cheat sheets on different technos (network, CLI tools, etc)
* \[G|C] [odat]: exploitation tools targeting oracle database
* \[G|C] [msdat]: exploitation tools targeting Microsoft SQL database
* \[G|C] [ShellPop]: generate bind/reverse shells from command line

### Sec/Tools list

* \[W] [pax0r]: another huge list of tools
* \[G] [SecLists]: SecLists is the security tester's companion. It is a collection of multiple types of lists used during security assessments
* \[G] [ctf-tools]: list of tools similar to this one
* \[I] http://resources.infosecinstitute.com/tools-of-trade-and-resources-to-prepare-in-a-hacker-ctf-competition-or-challenge/
* \[G] https://github.com/Hack-with-Github/Awesome-Hacking: awesome list related to hacking

### Programming

* \[I] http://www.tutorialspoint.com/: online programmation on most languages
* \[I] https://gcc.godbolt.org/: check disassembly code produced with different versions of gcc


---

If you wanna improve or add your tool here, fork this repo then push onto your own master then make a pull request.
I won't accept any software that is specific to OS X if it doesn't work on linux or windows.
If you think you have a nice feature idea, open an issue.
This list isn't mean to be ordered in some way, but if people like it, it is already noted that making a proper wiki referencing tools name with link might be a better thing than a Markdown page.
Github wiki is also an option when the list is going to be too long.


[DirBuster]: https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
[xortool]: https://github.com/hellman/xortool
[cribdrag]: https://github.com/SpiderLabs/cribdrag
[Cuckoo]: http://www.cuckoosandbox.org/
[Reflector]: https://www.red-gate.com/products/dotnet-development/reflector/
[Simple Assembly Explorer]: https://sites.google.com/site/simpledotnet/simple-assembly-explorer
[de4dot]: http://de4dot.com/
[IDA]: https://www.hex-rays.com/products/ida/
[OllyDbg]: http://www.ollydbg.de/
[x64dbg]: http://x64dbg.com/
[sqlmap]: http://sqlmap.org/
[Photorec]: http://www.cgsecurity.org/wiki/PhotoRec
[hash_extender]: https://github.com/iagox86/hash_extender
[hash-identifier]: https://github.com/psypanda/hashID
[lsb-toolkit]: https://github.com/luca-m/lsb-toolkit
[john]: http://www.openwall.com/john/
[volatility]: http://www.volatilityfoundation.org/
[Burp suite]: https://portswigger.net/burp/
[fiddler]: http://www.telerik.com/fiddler
[metasploit]: http://www.metasploit.com/
[exiftags]: http://johnst.org/sw/exiftags/
[hashcat]: http://hashcat.net/oclhashcat/
[HackBar]: https://chrome.google.com/webstore/detail/hackbar/ejljggkpbkchhfcplgpaegmbfhenekdc
[EditThisCookie]: https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?
[TamperData]: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
[Advanced Cookie Manager]: https://addons.mozilla.org/fr/firefox/addon/cookie-manager/
[Modify Headers]: https://addons.mozilla.org/fr/firefox/addon/modify-headers/
[HTTP Requester]: https://addons.mozilla.org/fr/firefox/addon/httprequester/
[FlagFox]: https://addons.mozilla.org/fr/firefox/addon/flagfox/
[Live HTTP Headers]: https://addons.mozilla.org/fr/firefox/addon/live-http-headers/
[ModHeader]: https://chrome.google.com/webstore/detail/modheader/idgpnmonknjnojddfkpgkljpfnnfcklj
[Netcat]: http://nc110.sourceforge.net/
[nmap]: https://nmap.org/
[binutils]: https://www.gnu.org/software/binutils/
[vmware]: http://www.vmware.com/
[dede]: http://www.softpedia.com/get/Programming/Debuggers-Decompilers-Dissasemblers/DeDe.shtml
[tweakpng]: http://entropymine.com/jason/tweakpng/
[dex2jar]: https://github.com/pxb1988/dex2jar
[kali]: https://www.kali.org/
[notepad++]: https://notepad-plus-plus.org/
[ctf-tools]: https://github.com/zardus/ctf-tools
[gdb]: https://www.gnu.org/software/gdb/
[peda]: https://github.com/longld/peda
[Stegsolve]: http://www.caesum.com/handbook/Stegsolve.jar
[Scapy]: http://www.secdev.org/projects/scapy/
[Nikto2]: https://cirt.net/Nikto2
[Autopsy/Sleuth]: http://www.sleuthkit.org/index.php
[Foremost]: https://doc.ubuntu-fr.org/foremost
[Aircrack]: http://www.aircrack-ng.org/
[Pin]: https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool
[Pintool]: https://github.com/wagiro/pintool
[pwntools]: https://pwntools.readthedocs.org/en/2.2/
[QEMU]: http://wiki.qemu.org/Main_Page
[rsatool]: https://github.com/ius/rsatool
[checksec]: http://www.trapkit.de/tools/checksec.html
[Detect it easy]: http://ntinfo.biz/
[Qira]: https://github.com/BinaryAnalysisPlatform/qira
[Hydra]: https://github.com/vanhauser-thc/thc-hydra
[ROPGadget]: https://github.com/JonathanSalwan/ROPgadget
[plasma]: https://github.com/joelpx/plasma
[XOCopy]: http://reverse.lostrealm.com/tools/xocopy.html
[Shellsploit]: https://github.com/b3mb4m/shellsploit-framework
[radare2]: https://github.com/radare/radare2
[Bokken]: https://github.com/radare/bokken
[BinWalk]: https://github.com/devttys0/binwalk
[Wbstego]: http://wbstego.wbailer.com/
[dff]: http://www.arxsys.fr/discover/
[origami]: https://github.com/cogent/origami-pdf
[libformatstr]: https://github.com/hellman/libformatstr
[fixenv]: https://github.com/hellman/fixenv
[cheatengine]: http://www.cheatengine.org/
[AutoLocalPrivilegeEscalation]: https://github.com/ngalongc/AutoLocalPrivilegeEscalation
[Voltron]: https://github.com/snare/voltron
[SecLists]: https://github.com/danielmiessler/SecLists
[PadBuster]: https://github.com/GDSSecurity/PadBuster
[Z3]: https://github.com/Z3Prover/z3
[angr]: https://github.com/angr/angr
[rop-tool]: https://github.com/t00sh/rop-tool
[villoc]: https://github.com/wapiflapi/villoc
[sshpass]: https://sourceforge.net/projects/sshpass/files/sshpass/
[Wireshark]: https://www.wireshark.org/
[binjitsu]: https://github.com/binjitsu/binjitsu
[virt-what]: https://people.redhat.com/~rjones/virt-what/
[valgrind]: http://valgrind.org/
[ProcessHacker]: http://processhacker.sourceforge.net/
[apimonitor]: http://www.rohitab.com/apimonitor
[pax0r]: http://pax0r.com/staff/tools2016/
[PEiD]: https://www.aldeid.com/wiki/PEiD
[ImpREC]: http://www.woodmann.com/collaborative/tools/index.php/ImpREC
[Flawfinder]: http://www.dwheeler.com/flawfinder/
[ExifTool]: http://www.sno.phy.queensu.ca/~phil/exiftool/
[NetworkMiner]: http://www.netresec.com/?page=NetworkMiner
[english-words]: https://github.com/dwyl/english-words
[MFTDump]: http://malware-hunters.net/all-downloads/
[AppCompatCacheParser]: https://github.com/EricZimmerman/AppCompatCacheParser
[RegistryExplorer]: https://binaryforay.blogspot.fr/2015/07/registry-explorerrecmd-0710-released.html
[python-paddingoracle]: https://github.com/mwielgoszewski/python-paddingoracle
[afl]: https://github.com/mirrorer/afl
[Hexinject]: https://sourceforge.net/projects/hexinject/files/
[gef]: https://github.com/hugsy/gef
[gdbgui]: https://github.com/cs01/gdbgui/
[wuzz]: https://github.com/asciimoo/wuzz
[one_gadget]: https://github.com/david942j/one_gadget
[Ropper]: https://github.com/sashs/Ropper
[fuzzdb]: https://github.com/fuzzdb-project/fuzzdb
[manticore]: https://github.com/trailofbits/manticore
[XNResourceEditor]: https://stefansundin.github.io/xn_resource_editor/
[FindCrypt2]: http://www.hexblog.com/?p=28
[ScyllaHide]: https://github.com/x64dbg/ScyllaHide/
[DIE]: https://github.com/ynvb/DIE
[processmonitor]: https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
[recon-ng]: https://bitbucket.org/LaNMaSteR53/recon-ng
[dnSpy]: https://github.com/0xd4d/dnSpy
[wfuzz]: https://github.com/xmendez/wfuzz
[patator]: https://github.com/lanjelot/patator
[impacket]: https://github.com/CoreSecurity/impacket
[Agent Ransack]: https://www.mythicsoft.com/agentransack/
[UACME]: https://github.com/hfiref0x/UACME/
[frida]: https://github.com/frida/frida
[objection]: https://github.com/sensepost/objection
[teh_s3_bucketeers]: https://github.com/tomdev/teh_s3_bucketeers
[apktool]: https://github.com/iBotPeaches/Apktool
[uber-apk-signer]: https://github.com/patrickfav/uber-apk-signer
[brakeman]: https://github.com/presidentbeef/brakeman
[gixy]: https://github.com/yandex/gixy
[mimikatz]: https://github.com/gentilkiwi/mimikatz
[pypykatz]: https://github.com/skelsec/pypykatz
[responder]: https://github.com/SpiderLabs/Responder
[crackmapexec]: https://github.com/byt3bl33d3r/CrackMapExec
[lsassy]: https://github.com/Hackndo/lsassy
[dumpert]: https://github.com/outflanknl/Dumpert
[odat]: https://github.com/quentinhardy/odat
[msdat]: https://github.com/quentinhardy/msdat
[phys2memprofit]: https://github.com/FSecureLABS/physmem2profit
[pywerview]: https://github.com/the-useless-one/pywerview
[SharpRDP]: https://github.com/0xthirteen/SharpRDP
[ssf]: https://github.com/securesocketfunneling/ssf
[revsocks]: https://github.com/kost/revsocks
[ShellPop]: https://github.com/0x00-0x00/ShellPop
