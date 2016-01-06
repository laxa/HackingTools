# This is a simple list of all tools that can be related to hacking, there are windows and linux tools

This repo was created and is updated by [Geluchat][(https://github.com/Geluchat) and [laxa](https://github.com/Laxa)
The overall idea is to find quickly a tool that could suits your need or help you in any way related to computer hacking.
This list is suppose to be as exhaustive as possible.

All tools are listed like this \[TAG1|\[TAG2|TAG3...]][Clickable name](#): Short description

Legend:
* \[G]: Github/Git repository # Note, this flag automatically imply the \[O] flag
* \[S]: Software (Imply that it's not always 100% free and that it's not open source or restrictive license)
* \[F]: Freeware (Free software, does'nt necesselary means that it's opensource)
* \[W]: Website
* \[P]: Plugin for chrome
* \[X]: Plugin for firefox
* \[C]: CLI tool
* \[O]: Open source
* \[M]: Misceallenous

Tool list:

* \[F|O][DirBuster]: bruteforce/dictionnary attack on webserver to find hidden directories
* \[C|G][xortool]: find xor key/key length from xor text/binary
* \[C|G][cribdrag]: interactive crib dragging on xored text
* \[F|O][Cuckoo]: interactive sandbox malware analysis for windows
* \[W]https://malwr.com/: online binary analysis
* \[W]https://retdec.com/: online decompiler for c/c++ binaries
* \[S][Reflector]: assembly browser for .NET
* \[F|O][Simple Assembly Explorer]: another .NET disassembler
* \[F|O][de4dot]: .NET deobfuscator
* \[S][IDA]: Windows debugger
* \[F|O][OllyDbg]: Windows debugger
* \[F|O][x64dbg]: Windows debugger
* \[C|O][sqlmap]: sql injection
* \[C|O][strace/ltrace]: static call tracers / dynamic call tracers (librairies)
* \[F|O][Photorec]: recover erased file
* \[C|G][hash_extender]: hash extension forger
* \[C|G][hash-identifier]: hash identifier
* \[C|G][lsb-toolkit]: extract bit from images for steganography
* \[C|O][john]: hash cracker (bruteforce + dico attacks)
* \[C|O][volatility]: forensic tool to analyse memory dump from windows/linux
* \[S][Burp]: request tool analysis/forge request
* \[S][fiddler]: HTTP web proxy
* \[C|S][metasploit]: Generate payload and browser exploits
* \[C|F][exiftags]: linux package to check jpg tags
* \[F|O][hashcat]: hash bruteforce cracker for windows that support GPU
* \[W]http://requestb.in/: get a temporary page to receive GET/POST request
* \[W]http://pastebin.com/: paste code/text with coloration
* \[W]http://portquiz.net/: test outgoing ports
* \[W]http://botscout.com/: check if an IP is flagged as spam/bot
* \[P|X][HackBar]: xss/sql tests
* \[P][EditThisCookie]: edit cookie, can lock cookie
* \[X][TamperData]: modify and tamper HTTP requests
* \[P][ModHeader]: edit HTTP requests
* \[C|O][Netcat]: network tool, can listen or connect using TCP/UDP
* \[C|O][nmap]: network tool to scan ports and discover services
* \[C|O][binutils]: tons of CLI tools
* \[S][vmware]: virtualization products
* \[S][dede]: delphi decompiler
* \[W]https://dnsdumpster.com/: free domain research tools, find subdomains
* \[W]https://pentest-tools.com/home: subdomain bruteforce not 100% free
* \[F|O][tweakpng]: windows tool to resize image for steganography
* \[W]https://regex101.com/: javascript/python/php regex online
* \[W]http://rubular.com/: ruby regex online
* \[G][dex2jar]: apk unpacker (android package)
* \[M|O][kali]: hacking linux OS
* \[W]http://www.tutorialspoint.com/: online programmation on most languages
* \[F|O][notepad++]: Windows text editor


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
