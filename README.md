# This is a simple list of all tools that can be related to hacking, there are windows and linux tools

This repo was created by [Geluchat](https://github.com/Geluchat) and [laxa](https://github.com/Laxa)
The overall idea is to find quickly a tool that could suits your need or help you in any way related to computer hacking.
This list is suppose to be as exhaustive as possible.

All tools are listed like this \[TAG1|\[TAG2|TAG3...]][Clickable name](#): Short description

### Legend

* \[G]: Github/Git repository # Note, this flag automatically imply the \[O] flag
* \[S]: Software (Imply that it's not always 100% free and that it's not open source or restrictive license)
* \[F]: Freeware (Free software, does'nt necesselary means that it's opensource)
* \[I]: Website
* \[P]: Plugin for chrome
* \[R]: Plugin for firefox
* \[C]: CLI tool
* \[O]: Open source
* \[M]: Misceallenous
* \[L]: Reverse Flag: is set only when Linux compatible
* \[W]: Reverse Flag: is set only when Windows comptabile

### Binary

* \[I] https://malwr.com/: online binary analysis
* \[I] https://retdec.com/: online decompiler for c/c++ binaries
* \[S|W] [Reflector]: assembly browser for .NET
* \[F|O|W] [Simple Assembly Explorer]: another .NET disassembler
* \[F|O|W] [de4dot]: .NET deobfuscator
* \[S] [IDA]: debugger
* \[F|O] [OllyDbg]: debugger
* \[F|O|W] [x64dbg]: debugger
* \[C|O|L] [gdb]: Gnu debugger for linux
* \[M] [peda]: python plugin for gdb
* \[C|O|L] [strace/ltrace]: system call tracers / dynamic call tracers (librairies)
* \[G] [dex2jar]: apk unpacker (android package)
* \[S] [dede]: delphi decompiler

### Forensic

* \[C|O] [volatility]: forensic tool to analyse memory dump from windows/linux

### Cryptography

* \[C|G] [xortool]: find xor key/key length from xor text/binary
* \[C|G] [cribdrag]: interactive crib dragging on xored text
* \[C|G] [hash_extender]: hash extension forger
* \[C|G] [hash-identifier]: hash identifier
* \[C|G] [lsb-toolkit]: extract bit from images for steganography
* \[C|O] [john]: hash cracker (bruteforce + dico attacks)
* \[F|O] [hashcat]: hash bruteforce cracker that support GPU

### Web

* \[F|O] [DirBuster]: bruteforce/dictionnary attack on webserver to find hidden directories
* \[I] http://pkav.net/XSS2.png: XSS spreadsheet
* \[C|O] [sqlmap]: sql injection
* \[S] [Burp]: request tool analysis/forge request
* \[S|W] [fiddler]: HTTP web proxy
* \[I] http://requestb.in/: get a temporary page to receive GET/POST request
* \[I] http://pastebin.com/: paste code/text with coloration
* \[I] http://portquiz.net/: test outgoing ports
* \[I] http://botscout.com/: check if an IP is flagged as spam/bot
* \[P|R] [HackBar]: xss/sql tests
* \[R] [TamperData]: modify and tamper HTTP requests
* \[P] [ModHeader]: edit HTTP requests
* \[P] [EditThisCookie]: edit cookie, can lock cookie
* \[I] https://dnsdumpster.com/: free domain research tools, find subdomains
* \[I] https://pentest-tools.com/home: subdomain bruteforce not 100% free

### Network

* \[C|O] [Netcat]: network tool, can listen or connect using TCP/UDP
* \[C|O] [nmap]: network tool to scan ports and discover services
* \[C|O] [Scapy]: powerful interactive packet manipulation program

### Steganography

* \[C|F] [exiftags]: linux package to check jpg tags
* \[F|O|W] [tweakpng]: tool to resize image for steganography
* \[F|O] [Stegsolve]: perform quick image analysis to find hidden things

### Misc

* \[F|O|W] [Cuckoo]: interactive sandbox malware analysis
* \[F|O|W] [Photorec]: recover erased file
* \[C|S] [metasploit]: Generate payload and browser exploits
* \[C|O] [binutils]: tons of CLI tools
* \[S] [vmware]: virtualization products
* \[I] https://regex101.com/: javascript/python/php regex online
* \[I] http://rubular.com/: ruby regex online
* \[M|O] [kali]: hacking linux OS
* \[G] [ctf-tools]: list of tools similar to this one
* \[I] https://www.exploit-db.com/: exploits database

### Programming

* \[I] http://www.tutorialspoint.com/: online programmation on most languages


---

If you wanna improve or add your tool here, fork this repo then push onto your own master then make a pull request.
I won't accept any software that is specific to OS X if it does'nt work on linux or windows.
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
[Burp]: https://portswigger.net/burp/
[fiddler]: http://www.telerik.com/fiddler
[metasploit]: http://www.metasploit.com/
[exiftags]: http://johnst.org/sw/exiftags/
[hashcat]: http://hashcat.net/oclhashcat/
[HackBar]: https://chrome.google.com/webstore/detail/hackbar/ejljggkpbkchhfcplgpaegmbfhenekdc
[EditThisCookie]: https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?
[TamperData]: https://addons.mozilla.org/en-US/firefox/addon/tamper-data/
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
