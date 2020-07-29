# File-Replacer
A Python script that can replace the file with any other file requested by a user. 

This script works in co-ordination with ARP Spoofing, it's main purpose is to intercept any file (image, pdf, .exe, etc.) requested by the remote victim machine and replace the requested file with any other file (image, pdf, .exe) that we want to. The ARP Spoofing allows us to become **Man In The Middle** which in turn routes all the network traffic of the remote victim machine through the attacker's machine. Then, the **File-Replacer** script checks for HTTP requests for particular file type and as soon as it encouters the HTTP Request for that file type, it replaces the contents of HTTP Response with the file that the attacker wants. 
