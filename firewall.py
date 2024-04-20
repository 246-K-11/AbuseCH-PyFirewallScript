import requests,subprocess, re

#Source = Abuse CH
getBotIpList = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt").text

rule= "netsh advfirewall firewall delete rule name='BadBotIp'"
subprocess.run(["Powershell", "-Command",rule])

fileLines = getBotIpList.splitlines()

for words in fileLines:
     #Match lines that begin with # to filter them
     notIp = re.search("^#.*",words) 
     #Execute if line does not start with # address
     if not notIp:
       ip = re.search("[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", words)
       #Execute if line is indeed an Ip address
       if ip:
         print("Added rule to block Ip:",words)
         rule = "netsh advfirewall firewall add rule name='BadBotIP' Dir=Out Action=Block RemoteIP="+words
         subprocess.run(["Powershell", "-Command",rule])
         #Line does not start with # but is not a valid Ip adress
       else: print("Line does not start with '#' but is NOT an IP address")


