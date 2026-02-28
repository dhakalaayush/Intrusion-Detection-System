import time
import re

iplist = [] #initialize the list of ip addresses sending requests

#initializing the attack counts
sql_attacks = 0
malwares = 0
brute_force_attacks = 0

def main():
    request = {} #initialize the request dictionary
    start_time = time.time() #set start_time
    
    #from the of sql injection payloads file, make a list of those payloads
    sqlPayloads = []
    with open("sqlinjectionpayloads.txt","r") as f:
        for each in f:
            if each.strip():
                sqlPayloads.append(each.strip())
            
    #from the malware keywords file, make a list of those payloads
    malwarePayloads = []
    with open("malwarepayloads.txt","r") as f:
        for each in f:
            if each.strip():
                malwarePayloads.append(each.strip())
    
    with open("log.txt","r") as file:
        #read the end of the file
        file.seek (0,2) #Change the cursor to offset 0 (number of bytes to move) and whence 2 (end of the file)
        while True: #infinity loop
             #clear request dictionary after 5 seconds
            current_time = time.time()
            if current_time - start_time > 5:
                request = {}
                start_time = time.time()
            line=file.readline() #read the file line
            
            #get ip address
            ip = None
            patterns = [
                r"(?i)(?:from|src|client|remote(?:_| )?addr|remote-ip)[=: ]*(\d{1,3}(?:\.\d{1,3}){3})",
                r"(\d{1,3}(?:\.\d{1,3}){3}) - -",
                r"(\d{1,3}(?:\.\d{1,3}){3})[^0-9.]",           # IP followed by non-IP char
                r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",        # standalone anywhere (last resort)
            ]
            for pat in patterns:
                m = re.search(pat, line, re.IGNORECASE)
                if m:
                    ip = m.group(1).strip()
                    break
            if ip:
                iplist = ipbook(ip)
                with open("ip.txt", "r+") as f:
                    # Read existing IPs and remove newline
                    existing_ips = set(line.strip() for line in f.readlines())

                    # Add new IPs
                    new_ips = [each for each in iplist if each not in existing_ips]
                    for ip_addr in new_ips:
                        f.write(f"{ip_addr}\n")

                        
            #bruteforce
            message = bruteforce(line,request,ip)
            if message !=1:
                print(line)
                if message != "":
                    with open("alerts.txt","a") as f:
                        f.write(f"{message}\n")
            
            #sqlinjection
            message = sqlinjection(line,sqlPayloads,ip)
            if message !=1:
                if message != "":
                    with open("alerts.txt","a") as f:
                        f.write(f"{message}\n")
                    
            #malwaredetection
            message = malwaredetection(line,malwarePayloads,ip)
            if message !=1:
                if message != "":
                    with open("alerts.txt","a") as f:
                        f.write(f"{message}\n")
    

def bruteforce(line,request,ip):
    global brute_force_attacks
    message = ""
            
    if not line: #if no new logs are added in the file
        time.sleep(1) #pause for a second to rest and consume less processing
        return 1 #return to main function continue to read again
            
    #check for brute force

    date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
    if not date:
        date = re.search(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}",line)
        if not date:
            date = "Couldn't resolve date"
        else:
            date = date.group()
    else:
        date = date.group()
        
        
    #check if login was successful
    if "Accepted password" in line:
        message = f"{date} Login alert: {ip} successfully logged in."
    
    elif "Invalid user" or "Failed password" in line:
        #check for number of requests
        if ip in request:
            request[ip] += 1 #increment the count of ip
        elif ip not in request:
            request[ip] = 1
        if request[ip] > 3:
            brute_force_attacks += 1
            message = f"{date} Multiple failed login attempts from {ip}. Potential Brute Force alert"
                    
    return message


def sqlinjection(line,payloads,ip):
    global sql_attacks
    for each in payloads:
        if each.lower() in line.lower():
            date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
            if not date:
                date = re.search(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}",line)
                if not date:
                    date = "Couldn't resolve date"
                else:
                    date = date.group()
            else:
                date = date.group()
            sql_attacks += 1
            return f"{date} SQL Injection alert from {ip}!"
    return 1


def malwaredetection(line,payloads,ip):
    global malwares
    for each in payloads:
        if each.lower() in line.lower():
            date = re.search(r"\b[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}\b",line)
            if not date:
                date = re.search(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}",line)
                if not date:
                    date = "Couldn't resolve date"
                else:
                    date = date.group()
            else:
                date = date.group()
            malwares += 1
            return f"{date} Suspicious Action alert from {ip}!"
    return 1

def ipbook(ip):
    global iplist
    if ip not in iplist:
        iplist.append(ip)
    return iplist


def process_new_logs():
    global sql_attacks, malwares, brute_force_attacks
    new_sql = 0
    new_malware = 0
    new_brute = 0
    
    new_sql += 1 

    # update global counters
    sql_attacks += new_sql
    malwares += new_malware
    brute_force_attacks += new_brute
    
def get_sql_attacks():
    return sql_attacks
def get_malwares():
    return malwares
def get_brute_force_attacks():
    return brute_force_attacks


if __name__ == "__main__":
    main()
    