# 100-hacking-tools
100 Hacking Tools and Resources

### **Burp Suite**

1. [Burp Suite](https://portswigger.net/burp): The quintessential web app hacking tool. Check out these awesome Burp plugins:

2. [ActiveScan++](https://portswigger.net/bappstore/3123d5b5f25c4128894d97ea1acc4976): ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead, it identifies application behavior that may be of interest to advanced testers.

3. [BurpSentinel](https://github.com/dobin/BurpSentinel): With BurpSentinel it is possible for the penetration tester to quickly and easily send a lot of malicious requests to parameters of a HTTP request. Not only that, but it also shows a lot of information of the HTTP responses, corresponding to the attack requests. It's easy to find low-hanging fruit and hidden vulnerabilities like this, and it also allows the tester to focus on more important stuff!

4. [Autorepeater Burp](https://github.com/nccgroup/AutoRepeater): Automated HTTP request repeating with Burp Suite. 

5. [Autorize](https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f) Burp: Autorize is an extension aimed at helping the penetration testers to detect authorization vulnerabilities, one of the more time-consuming tasks in a web application penetration test.

6. [Burp Beautifier](https://portswigger.net/bappstore/a005a6a8fba34a8893ec649f76a8d5a7): BurpBeautifier is a Burpsuite extension for beautifying request/response body, supporting JS, JSON, HTML, XML format, writing in Jython 2.7.

7. [Flow](https://portswigger.net/bappstore/ee1c45f4cc084304b2af4b7e92c0a49d): This extension provides a Proxy history-like view along with search filter capabilities for all Burp tools.

8. [Headless Burp](https://portswigger.net/bappstore/d54b11f7af3c4dfeb6b81fb5db72e381): This extension allows you to run Burp Suite's Spider and Scanner tools in headless mode via the command-line.

9. [Logger++:](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81) Logger++ is a multi-threaded logging extension for Burp Suite. In addition to logging requests and responses from all Burp Suite tools, the extension allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter.

10. [WSDL Wizard:](https://portswigger.net/bappstore/ef2f3f1a593d417987bb2ddded760aee) This extension scans a target server for WSDL files. After performing normal mapping of an application's content, right click on the relevant target in the site map, and choose "Scan for WSDL files" from the context menu. The extension will search the already discovered contents for URLs with the .wsdl file extension, and guess the locations of any additional WSDL files based on the file names known to be in use. The results of the scanning appear within the extension's output tab in the Burp Extender tool.

11. [JSON_Beautifier](https://portswigger.net/bappstore/309ef28d45ff4f19bedfed3896cb3ca9): This plugin provides a JSON tab with beautified representation of the request/response.

### **Web Hacking**

12. [JSParser](https://github.com/nahamsec/JSParser): A python 2.7 script using Tornado and JSBeautifier to parse relative URLs from JavaScript files. This is especially useful for discovering AJAX requests when performing security research or bug bounty hunting.

13. [Knockpy](https://github.com/guelfoweb/knock): Knockpy is a python tool designed to enumerate subdomains on a target domain through a word list. It is designed to scan for a DNS zone transfer and bypass the wildcard DNS record automatically, if it is enabled. Knockpy now supports queries to VirusTotal subdomains, you can set the API_KEY within the config.json file.

14. [Lazys3](https://github.com/nahamsec/lazys3): A Ruby script to brute-force for AWS s3 buckets using different permutations.

15. [Sublist3r](https://github.com/aboul3la/Sublist3r): Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT. It helps penetration testers and bug hunters collect and gather subdomains for the domain they are targeting. Sublist3r enumerates subdomains using many search engines such as Google, Yahoo, Bing, Baidu and Ask. Sublist3r also enumerates subdomains using Netcraft, Virustotal, ThreatCrowd, DNSdumpster and ReverseDNS.

16. [Teh_s3_bucketeers](https://github.com/tomdev/teh_s3_bucketeers): Teh_s3_bucketeers is a security tool to discover S3 buckets on Amazon's AWS platform. 

17. [Virtual-host-discovery](https://github.com/jobertabma/virtual-host-discovery): This is a basic HTTP scanner that enumerates virtual hosts on a given IP address. During recon, this might help expand the target by detecting old or deprecated code. It may also reveal hidden hosts that are statically mapped in the developer's /etc/hosts file.

18. [Wpscan](https://github.com/wpscanteam/wpscan): WPScan is a free (for non-commercial use) black box WordPress security scanner written for security professionals and bloggers to test the security of their sites.

19. [Webscreenshot](https://github.com/maaaaz/webscreenshot): A simple script to screenshot a list of websites, based on the url-to-image PhantomJS script.

20. [Asnlookup](https://www.ultratools.com/tools/asnInfo): The ASN Information tool displays information about an IP address's Autonomous System Number (ASN), such as: IP owner, registration date, issuing registrar and the max range of the AS with total IPs.

21. [Unfurl](https://github.com/JLospinoso/unfurl): Unfurl is a tool that analyzes large collections of URLs and estimates their entropies to sift out URLs that might be vulnerable to attack.

22. [Waybackurls](https://github.com/tomnomnom/waybackurls): Accept line-delimited domains on stdin, fetch known URLs from the Wayback Machine for *.domain and output them on stdout.

23. [Httprobe](https://github.com/tomnomnom/httprobe): Takes a list of domains and probes for working http and https servers.

24. [Meg](https://github.com/tomnomnom/meg): Meg is a tool for fetching lots of URLs without taking a toll on the servers. It can be used to fetch many paths for many hosts, or fetching a single path for all hosts before moving on to the next path and repeating.

25. [Gau](https://github.com/lc/gau): Getallurls (gau) fetches known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl for any given domain. Inspired by Tomnomnom's waybackurls.

26. [Ffuf](https://github.com/ffuf/ffuf): A fast web fuzzer written in Go.

27. [Dirsearch](https://github.com/maurosoria/dirsearch): A simple command line tool designed to brute force directories and files in websites.

28. [OWASP Zed](https://www.zaproxy.org/): OWASP Zed Attack Proxy (ZAP) is an open source tool which is offered by OWASP (Open Web Application Security Project), for penetration testing of your website/web application. It helps you find the security vulnerabilities in your application.

29. [Subfinder](https://github.com/projectdiscovery/subfinder): Subfinder is a subdomain discovery tool that discovers valid subdomains for websites by using passive online sources. It has a simple modular architecture and is optimized for speed. Subfinder is built for doing one thing only - passive subdomain enumeration, and it does that very well.

30. [EyeWitnees](https://github.com/FortyNorthSecurity/EyeWitness): EyeWitness is designed to take screenshots of websites, provide some server header info, and identify any default credentials. EyeWitness is designed to run on Kali Linux. It will auto detect the file you give it with the -f flag as either being a text file with URLs on each new line, nmap xml output, or nessus xml output. The --timeout flag is completely optional, and lets you provide the max time to wait when trying to render and screenshot a web page.

31. [Nuclei](https://github.com/projectdiscovery/nuclei): Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.

32. [Naabu](https://github.com/projectdiscovery/naabu): Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. It is a really simple tool that does fast SYN scans on the host/list of hosts and lists all ports that return a reply.

33. [Shuffledns](https://github.com/projectdiscovery/shuffledns): ShuffleDNS is a wrapper around massdns written in go that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.

34. [Dnsprobe](https://github.com/projectdiscovery/dnsprobe): DNSProbe is a tool built on top of retryabledns that allows you to perform multiple dns queries of your choice with a list of user supplied resolvers.

35. [Chaos](https://chaos.projectdiscovery.io/): Chaos actively scans and maintains internet-wide assets' data. This project is meant to enhance research and analyze changes around DNS for better insights.

36. [Subjack](https://github.com/haccer/subjack): Subjack is a Subdomain Takeover tool written in Go designed to scan a list of subdomains concurrently and identify ones that are able to be hijacked. With Go's speed and efficiency, this tool really stands out when it comes to mass-testing. Always double check the results manually to rule out false positives.

37. [gitGraber](https://github.com/hisxo/gitGraber): gitGraber is a tool developed in Python3 to monitor GitHub to search and find sensitive data in real time for different online services.

38. [Shhgit](https://github.com/eth0izzle/shhgit): Shhgit finds secrets and sensitive files across GitHub code and Gists committed in nearly real-time by listening to the GitHub Events API.

39. [Commit-stream](https://github.com/x1sec/commit-stream): Commit-stream extracts commit logs from the Github event API,  exposing the author details (name and email address) associated with Github repositories in real time.

40. [Masscan](https://github.com/robertdavidgraham/masscan): This is an Internet-scale port scanner. It can scan the entire Internet in under 6 minutes, transmitting 10 million packets per second, all from a single machine.

41. [Massdns](https://github.com/blechschmidt/massdns): MassDNS is a simple high-performance DNS stub resolver targeting those who seek to resolve a massive amount of domain names in the order of millions or even billions. Without special configuration, MassDNS is capable of resolving over 350,000 names per second using publicly available resolvers.

42. [Findomain](https://github.com/Edu4rdSHL/findomain): Findomain offers a dedicated monitoring service hosted in Amazon (only the local version is free), that allows you to monitor your target domains and send alerts to Discord and Slack webhooks or Telegram chats when new subdomains are found.

43. [Amass](https://github.com/OWASP/Amass): The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques.

44. [Dnsgen](https://github.com/ProjectAnte/dnsgen): This tool generates a combination of domain names from the provided input. Combinations are created based on wordlist. Custom words are extracted per execution.

45. [Dngrep](https://github.com/erbbysam/DNSGrep): A utility for quickly searching presorted DNS names. Built around the Rapid7 rdns & fdns dataset.

46. [Wfuzz](https://github.com/xmendez/wfuzz): Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

47. [Aquatone](https://github.com/michenriksen/aquatone): Aquatone is a tool for visual inspection of websites across a large number of hosts, which provides a convenient overview of HTTP-based attack surface.

48. [WhatWeb](https://github.com/urbanadventurer/WhatWeb): WhatWeb recognizes web technologies including content management systems (CMS), blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. WhatWeb has over 1800 plugins, each to recognise something different. WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.

49. [Dirb](https://github.com/v0re/dirb): ‘DIRB is a web content scanner. It launches a dictionary based attack against a web server and analyzes the response. 

50. [Dnscan](https://github.com/rbsec/dnscan): Dnscan is a python wordlist-based DNS subdomain scanner.

51. [Sublert](https://github.com/yassineaboukir/sublert): Sublert is a security and reconnaissance tool that was written in Python to leverage certificate transparency for the sole purpose of monitoring new subdomains deployed by specific organizations and an issued TLS/SSL certificate. The tool is supposed to be scheduled to run periodically at fixed times, dates, or intervals (Ideally each day). New identified subdomains will be sent to Slack workspace with a notification push. Furthermore, the tool performs DNS resolution to determine working subdomains.

52. [Recon-ng](https://github.com/lanmaster53/recon-ng): Recon-ng is a full-featured reconnaissance framework designed with the goal of providing a powerful environment to conduct open source, web-based reconnaissance quickly and thoroughly.

53. [Jok3r](https://hub.docker.com/r/koutto/jok3r/): Jok3r is a framework that helps penetration testers with network infrastructure and web security assessments. Its goal is to automate as much as possible in order to quickly identify and exploit "low-hanging fruit" and "quick win" vulnerabilities on most common TCP/UDP services and most common web technologies (servers, CMS, languages...).

54. [DirBuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project): This tool is a multi-threaded java application that is used to perform brute force over directories and file names on web and application servers. DirBuster attempts to find hidden directories and pages within a web application, providing users with an additional attack vector.

55. [Altdns](https://github.com/infosec-au/altdns): Altdns is a DNS recon tool that allows for the discovery of subdomains that conform to patterns. Altdns takes in words that could be present in subdomains under a domain (such as test, dev, staging), as well as a list of known subdomains.

56. [Recon_profile](https://github.com/nahamsec/recon_profile): This tool is to help create easy aliases to run via an SSH/terminal.  

57. [BBHT](https://github.com/nahamsec/bbht): Bug Bounty Hunting Tools is a script to install the most popular tools used while looking for vulnerabilities for a bug bounty program.

### **Mobile Hacking**

58. [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF): Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.

59. [Jadx](https://github.com/skylot/jadx): Jadx is a dex to Java decompiler. The command line and GUI tools for producing Java source code from Android Dex and Apk files. 

60. [Dex2Jar](https://github.com/pxb1988/dex2jar): Dex2Jar is a freely available tool to work with Android “. dex” and Java “. class” files. 

61. [Radare2](https://rada.re/n/): A free/libre toolchain for easing several low level tasks, such as forensics, software reverse engineering, exploiting, debugging, etc. It is composed by a large number of libraries (which are extended with plugins) and programs that can be automated with almost any programming language.

62. [Genymotion:](https://www.genymotion.com/) Cross-platform Android emulator for developers & QA engineers. Develop & automate your tests to deliver best quality apps.

63. [Frida "Universal" SSL Unpinner](https://gist.github.com/teknogeek/4dc35fb3801bd7f13e5f0da5b784c725): Universal unpinner. 

64. [Frida](https://frida.re/): Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.

### **Exploitation**

65. [SQLNinja](http://sqlninja.sourceforge.net/): Sqlninja is a tool targeted to exploit SQL Injection vulnerabilities on a web application that uses Microsoft SQL Server as its back-end.

66. [XSS hunter](https://xsshunter.com/): XSS Hunter allows you to find all kinds of cross-site scripting vulnerabilities, including the often-missed blind XSS. The service works by hosting specialized XSS probes which, upon firing, scan the page and send information about the vulnerable page to the XSS Hunter service.

67. [NoSQLMap](https://github.com/codingo/NoSQLMap): NoSQLMap is an open source Python tool designed to audit for, as well as automate injection attacks, and exploit default configuration weaknesses in NoSQL databases and web applications using NoSQL to disclose or clone data from the database. 

68. [Ysoserial](https://github.com/frohoff/ysoserial): A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. 

69. [Sqlmap](https://github.com/sqlmapproject/sqlmap): Sqlmap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester, and a broad range of switches including database fingerprinting, over data fetching from the database, accessing the underlying file system, and executing commands on the operating system via out-of-band connections.

70. [SSRFTest](https://github.com/daeken/SSRFTest): SSRF testing tool.

71. [Retire.JS](https://addons.mozilla.org/en-US/firefox/addon/retire-js/): Scanning website for vulnerable js libraries.

72. [Spiderfoot](https://github.com/smicallef/spiderfoot): SpiderFoot is an open source intelligence (OSINT) automation tool. It integrates with just about every data source available, and automates OSINT collection so that you can focus on data analysis.

### **Scanners/Frameworks**

73. [OpenVAS](https://www.openvas.org/): OpenVAS is a full-featured vulnerability scanner. Its capabilities include unauthenticated testing, authenticated testing, various high level and low-level Internet and industrial protocols, performance tuning for large-scale scans and a powerful internal programming language to implement any type of vulnerability test.

74. [Nikto](https://cirt.net/Nikto2): Nikto is an Open Source (GPL) web server scanner which performs comprehensive tests against web servers for multiple items, including over 6700 potentially dangerous files/programs, checks for outdated versions of over 1250 servers, and version specific problems on over 270 servers.

75. [Wapiti](https://wapiti.sourceforge.io/): Wapiti allows you to audit the security of your websites or web applications. It performs "black-box" scans (it does not study the source code) of the web application by crawling the web pages of the deployed webapp, looking for scripts and forms where it can inject data.

76. [Metasploit](https://www.metasploit.com/): Metasploit is an open-source penetration testing framework.

77. [Maltego](https://www.maltego.com/): Maltego is an open source intelligence (OSINT) and graphical link analysis tool for gathering and connecting information for investigative tasks.

78. [Canvas](https://www.immunityinc.com/products/canvas/): CANVAS offers hundreds of exploits, an automated exploitation system, and a comprehensive, reliable exploit development framework to penetration testers and security professionals worldwide.

79. [Sn1per](https://github.com/1N3/Sn1per): Sn1per Community Edition is an automated scanner that can be used during a penetration test to enumerate and scan for vulnerabilities. Sn1per Professional is Xero Security's premium reporting addon for Professional Penetration Testers, Bug Bounty Researchers and Corporate Security teams to manage large environments and pentest scopes.

80. [Lazyrecon](https://github.com/nahamsec/lazyrecon): LazyRecon is a script written in Bash, intended to automate the tedious tasks of reconnaissance and information gathering. The information is organized in an html report at the end, which helps you identify next steps.

81. [Osmedeus](https://github.com/j3ssie/Osmedeus): Osmedeus allows you to automatically run the collection of awesome tools for reconnaissance and vulnerability scanning against the target.

82. [Reconness](https://github.com/reconness/reconness): ReconNess helps you to run and keep all your #recon in the same place allowing you to focus only on the potentially vulnerable targets without distraction and without requiring a lot of bash skill, or programming skill in general.

83. [IronWASP](https://resources.infosecinstitute.com/ironwasp-part-1-2/): IronWASP (Iron Web Application Advanced Security testing Platform) is an open-source tool used for web application vulnerability testing. It is designed in such a way that users having the right knowledge can create their own scanners using this as a framework. IronWASP is built using Python and Ruby and users having knowledge of them would be able to make full use of the platform. However, IronWASP provides a lot of features that are simple to understand.

84. [Nmap](https://nmap.org/): Nmap ("Network Mapper") is a free and open-source (license) utility for network discovery and security auditing.

### **Datasets / Freemium Services** 

85. [Shodan](https://www.shodan.io/): Shodan provides a public API that allows other tools to access all of Shodan's data. Integrations are available for Nmap, Metasploit, Maltego, FOCA, Chrome, Firefox and many more.

86. [Censys](https://censys.io/): Censys scans the most ports and houses the biggest certificate database in the world, and provides the most up-to-date,  thorough view of your known and unknown assets.

87. [Rapid7 Forward DNS (FDNS)](https://opendata.rapid7.com/sonar.fdns_v2/): This dataset contains the responses to DNS requests for all forward DNS names known by Rapid7's Project Sonar. 

88. [C99.nl](https://api.c99.nl/): C99.nl is a scanner that scans an entire domain to find as many subdomains as possible.

89. [Seclists](https://github.com/danielmiessler/SecLists): SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more. The goal is to enable a security tester to pull this repository onto a new testing box and have access to every type of list that may be needed.

90. [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings): A list of useful payloads and bypasses for Web Application Security. Feel free to improve with your payloads and techniques. 

### **Miscellaneous Hacking Tools**

91. [Ettercap](https://www.ettercap-project.org/): Ettercap is a comprehensive suite which features sniffing of live connections, content filtering, and support for active and passive dissection of many protocols, including multiple features for network and host analysis.

92. [Transformations](https://transformations.jobertabma.nl/): Transformations makes it easier to detect common data obscurities, which may uncover security vulnerabilities or give insight into bypassing defenses. 

93. [John the Ripper](https://www.openwall.com/john/): John the Ripper is free and Open Source software, distributed primarily in a source code form.

94. [Wireshark](https://www.wireshark.org/): Wireshark® is a network protocol analyzer that lets you capture and interactively browse the traffic running on a computer network.  

95. [Foxyproxy](https://addons.mozilla.org/en-US/firefox/addon/foxyproxy-standard/): FoxyProxy is an advanced proxy management tool that completely replaces Firefox's limited proxying capabilities. For a simpler tool and less advanced configuration options, please use FoxyProxy Basic.

96. [Wappalyzer](https://addons.mozilla.org/en-US/firefox/addon/wappalyzer/): Wappalyzer is a browser extension that uncovers the technologies used on websites. It detects content management systems, eCommerce platforms, web servers, JavaScript frameworks, analytics tools and many more.

97. [Buildwith](https://addons.mozilla.org/en-US/firefox/addon/builtwith/): BuiltWith's goal is to help developers, researchers and designers find out what technologies web pages are using, which may help them decide what technologies to implement themselves.

98. [Altair](https://altair.sirmuel.design/): Altair GraphQL Client helps you debug GraphQL queries and implementations - taking care of the hard part so you can focus on actually getting things done.

99. [THC Hydra](https://github.com/vanhauser-thc/thc-hydra): This tool is a proof-of-concept code, designed to give researchers and security consultants the possibility to show how easy it would be to gain unauthorized access from remote to a system.

100. [Swiftness X](https://github.com/ehrishirajsharma/SwiftnessX): A note taking tool for BB and pentesting.
