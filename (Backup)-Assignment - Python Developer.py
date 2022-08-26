import requests
from http import HTTPStatus
import socket
import ssl
import datetime
import secure

#*********************** Subdomains ***********************#

domain_list = []                          # Create list for Counting Total Subdomains
def domain_scanner(domain_name,sub_domnames):
	print('-'*60)
	print("[+] Subdomains : ")
	for subdomain in sub_domnames:
		
		url = f"https://{subdomain}.{domain_name}"  # Formatting url with https://
		
		try:
			requests.get(url)             # Requests to url.
			value = HTTPStatus.OK.value   # Value of PORT
			phrase = HTTPStatus.OK.phrase # OK or NOT 

			if __name__ == '__main__':    # For Removing "https://" from url
				n = 8  
				url = url[n:]

			print(f'- [{value} {phrase}] {url}')
			domain_list.append(url)       # Append url in list

		except requests.ConnectionError:
			pass

if __name__ == '__main__':
    domain_name = input("Enter the Domain Name : ")     # Getting Domain name as an input.
    print("\n[+] " + "URL : " + domain_name)

    with open('sub-domain.txt','r') as file:	
        name = file.read()
		
        sub_domain = name.splitlines()                  # Spliting of name for proper output.
		
    domain_scanner(domain_name, sub_domain)

domain_count = len(domain_list)                         # Counting Total Subdomains
print(f"\n[+] Total Subdomains Found : {domain_count}") # Print Total Subdomains


#*********************** SSL Details ***********************#
def Get_SSL(hostname):
    print('-'*60)
    print("[+] SSL Details : ")
    
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'              # SSL Date Formatting
    context = ssl.create_default_context()              # Creating context for ssl

    connection = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname=hostname,)  # Wrap a socket
    connection.settimeout(3.0)
    connection.connect((hostname, 443))                                   # Connecting with hostname
    ssl_info = connection.getpeercert()
    Exp_ON=datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt) # Getting Expire date of ssl
    Days_Remaining= Exp_ON - datetime.datetime.utcnow()                   # Calculating remaining days for expire
    if Days_Remaining != 0:                                               # Condition if remaining days are not 0 then SSL is Enabled
        print("- SSL : Enabled")
    else:                                                                 # Condition else SSL is Blocked
        print("- SSL : Blocked")
    print ("- issued_to : " + "%s"%(hostname))                            # Name of host SSL issued to
    print('-'*60)
Get_SSL(domain_name)                                                      # Calling Get_SSL function


#*********************** Port ***********************#
ip = socket.gethostbyname(domain_name)             # Getting ip by hostename
port_list = [80,443,110,23,22]                      # List of ports
print("[+] Ports : ")
for port in port_list:
    socket_info = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Getting socket info of ports
    result = socket_info.connect_ex((ip, port))                      # Connecting ip and port with socket_info

    if result == 0:                                # Condition if result of connection is 0 then port is open
        print('Port ',port, ' : Open')

    elif result == 10060:                          # Condition if result of connection is 10060 then port is close
        print('Port ',port, ' : Closed')

    else:                                          # Condition else port is filtered
        print('Port ',port, ' : Filtered')


#*********************** X-XSS-Protection ***********************#

secure_headers = secure.Secure()     # Getting Secure Headers       
print('-'*60)
print("[+] Header : ")
with open("X-XSS.txt","w") as f:
    f.write(str(secure_headers))     # Saving Headers in file for getting only value of X-XSS-Protection

with open(r'X-XSS.txt', 'r') as file:  # Reading file

        content = file.read()
        if 'X-XSS-Protection:0' in content:     # Condition if X-XSS-Protection is 0 then X-XSS-Protection is Enabled
            print('X-XSS-Protection : Enabled')
        elif 'X-XSS-Protection:1' in content:   # Condition otherwise X-XSS-Protection is Blocked
            print('X-XSS-Protection : Blocked')
            