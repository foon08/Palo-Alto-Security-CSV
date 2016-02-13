# Copy the set commands for the PA Security Policy below to declare as variable rules
rules = '''set vsys vsys1 rulebase security rules Permit_IKE profile-setting group "Threat Protection"
set vsys vsys1 rulebase security rules Permit_IKE to Cross
set vsys vsys1 rulebase security rules Permit_IKE from Cross
set vsys vsys1 rulebase security rules Permit_IKE source VPN_Peers
set vsys vsys1 rulebase security rules Permit_IKE destination VPN_Peers
set vsys vsys1 rulebase security rules Permit_IKE source-user any
set vsys vsys1 rulebase security rules Permit_IKE category any
set vsys vsys1 rulebase security rules Permit_IKE application ike
set vsys vsys1 rulebase security rules Permit_IKE service application-default
set vsys vsys1 rulebase security rules Permit_IKE hip-profiles any
set vsys vsys1 rulebase security rules Permit_IKE action allow
set vsys vsys1 rulebase security rules Permit_IKE log-start yes
set vsys vsys1 rulebase security rules Permit_IKE log-setting "Traffic and Syslog"
set vsys vsys1 rulebase security rules Permit_OSPF profile-setting group "Threat Protection"
set vsys vsys1 rulebase security rules Permit_OSPF to VPN
set vsys vsys1 rulebase security rules Permit_OSPF from VPN
set vsys vsys1 rulebase security rules Permit_OSPF source OSPF_Peers
set vsys vsys1 rulebase security rules Permit_OSPF destination OSPF_Peers
set vsys vsys1 rulebase security rules Permit_OSPF source-user any
set vsys vsys1 rulebase security rules Permit_OSPF category any
set vsys vsys1 rulebase security rules Permit_OSPF application ospf
set vsys vsys1 rulebase security rules Permit_OSPF service application-default
set vsys vsys1 rulebase security rules Permit_OSPF hip-profiles any
set vsys vsys1 rulebase security rules Permit_OSPF action allow
set vsys vsys1 rulebase security rules Permit_OSPF log-start yes
set vsys vsys1 rulebase security rules Permit_OSPF log-setting "Traffic and Syslog"
set vsys vsys1 rulebase security rules Site_to_Site to VPN
set vsys vsys1 rulebase security rules Site_to_Site from Management
set vsys vsys1 rulebase security rules Site_to_Site source Mgt-10.2.1.0-24
set vsys vsys1 rulebase security rules Site_to_Site destination Atl_Network_Devices
set vsys vsys1 rulebase security rules Site_to_Site source-user any
set vsys vsys1 rulebase security rules Site_to_Site category any
set vsys vsys1 rulebase security rules Site_to_Site application [ ping ssh ssl ]
set vsys vsys1 rulebase security rules Site_to_Site service application-default
set vsys vsys1 rulebase security rules Site_to_Site hip-profiles any
set vsys vsys1 rulebase security rules Site_to_Site action allow
set vsys vsys1 rulebase security rules Site_to_Site profile-setting group "Threat Protection"
set vsys vsys1 rulebase security rules Site_to_Site log-start yes
set vsys vsys1 rulebase security rules Site_to_Site log-setting "Traffic and Syslog"
set vsys vsys1 rulebase security rules Mgt_to_DMZ to DMZ
set vsys vsys1 rulebase security rules Mgt_to_DMZ from Management
set vsys vsys1 rulebase security rules Mgt_to_DMZ source Mgt-10.3.1.0-24
set vsys vsys1 rulebase security rules Mgt_to_DMZ destination [ Web-2.3.1.4 DNS-67.40.34.65 Email-167.40.34.131 Plex-167.40.34.132 IRC-67.40.34.252 ]
set vsys vsys1 rulebase security rules Mgt_to_DMZ source-user any
set vsys vsys1 rulebase security rules Mgt_to_DMZ category any
set vsys vsys1 rulebase security rules Mgt_to_DMZ application [ ping ssh ssl ]
set vsys vsys1 rulebase security rules Mgt_to_DMZ service application-default
set vsys vsys1 rulebase security rules Mgt_to_DMZ hip-profiles any
set vsys vsys1 rulebase security rules Mgt_to_DMZ action allow
set vsys vsys1 rulebase security rules Mgt_to_DMZ profile-setting group "Threat Protection"
set vsys vsys1 rulebase security rules Mgt_to_DMZ log-start yes
set vsys vsys1 rulebase security rules Mgt_to_DMZ log-setting "Traffic and Syslog"
set vsys vsys1 rulebase security rules Management_Allow to VPN
set vsys vsys1 rulebase security rules Management_Allow from Management
set vsys vsys1 rulebase security rules Management_Allow source Mgt-10.2.1.0-24
set vsys vsys1 rulebase security rules Management_Allow destination LV_Network_Devices
set vsys vsys1 rulebase security rules Management_Allow source-user any
set vsys vsys1 rulebase security rules Management_Allow category any
set vsys vsys1 rulebase security rules Management_Allow application [ ping ssh ssl ]
set vsys vsys1 rulebase security rules Management_Allow service application-default
set vsys vsys1 rulebase security rules Management_Allow hip-profiles any
set vsys vsys1 rulebase security rules Management_Allow action allow
set vsys vsys1 rulebase security rules Management_Allow profile-setting group "Threat Protection"
set vsys vsys1 rulebase security rules Management_Allow log-start yes
set vsys vsys1 rulebase security rules Management_Allow log-setting "Traffic and Syslog"'''

#splits the rule so they can be parsed. Declares some variables to be used
rules_split = rules.split("\n")
a = {}
current_rule = ""

#Loop to Parse the config
for line in rules_split:

	entry = line.split()
	new_entry = entry[6:]
	name = new_entry[0:1]
	column = str(new_entry[1:2])
	config = str(" ".join(new_entry[2:]))
	column = column.strip("'[")
	column = column.strip("']")
	column = str(column)

# To determine once the parsing engine has gotten to the next rule
	if current_rule == "":
		current_rule = name
		a['name'] = str(name)
		a[column] = config
	elif current_rule == name:
		current_rule = name
		a['name'] = str(name)
		a[column] = config
	elif current_rule != name:
		#print '%60s %60s %60s %60s %60s %60s %60s %60s %60s' % (a['name'], a['from'], a['source'], a['to'], a['destination'], a['source-user'], a['application'], a['service'], a['action'])
		print '%s,%s,%s,%s,%s,%s,%s,%s,%s' % (a['name'], a['from'], a['source'], a['to'], a['destination'], a['source-user'], a['application'], a['service'], a['action'])
		current_rule = name
		a['name'] = str(name)
		a[column] = config
	

#print '%60s %60s %60s %60s %60s %60s %60s %60s %60s' % (a['name'], a['from'], a['source'], a['to'], a['destination'], a['source-user'], a['application'], a['service'], a['action'])
print '%s,%s,%s,%s,%s,%s,%s,%s,%s' % (a['name'], a['from'], a['source'], a['to'], a['destination'], a['source-user'], a['application'], a['service'], a['action'])
