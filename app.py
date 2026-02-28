from flask import Flask, render_template, jsonify
from loganalysis import get_sql_attacks, get_brute_force_attacks, get_malwares, main as generator
import threading,time

app = Flask(__name__)


#this function keeps reading access.log and auth.log and update log.txt
def monitor(logfile):
    with open(logfile, "r") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.5)
                continue

            with open("log.txt", "a") as f:
                f.write(line)
                f.flush() #write buffer into file


#this function keeps running the main function of loganalysis.py
def background_loganalysis():
    while True:
        generator()  # updates alerts.txt
        time.sleep(5)


#run loganalysis and logcollector in background
threading.Thread(target=background_loganalysis, daemon=True).start()
# start log collectors
threading.Thread(target=monitor, args=("/var/log/auth.log",), daemon=True).start()
threading.Thread(target=monitor, args=("/var/log/access.log",), daemon=True).start()



@app.route('/')
def read_logs():
    with open("log.txt","r") as file:
        logs = file.read()
        logs = logs.split("\n") #make list of logs
        
        #remove blank lines
        for each in logs[:]:
            if each == "":
                logs.remove(each)
                
        #keep last 10 logs
        logs = logs[-10:]
    

    with open("alerts.txt","r") as file:
        alerts = file.read()
        alerts = alerts.split("\n")
        
        #remove blank lines
        for each in alerts[:]:
            if each == "":
                alerts.remove(each)
                
        #keep last 10 alerts
        alerts = alerts[-10:]
        
    with open("ip.txt","r") as file:
        list = file.read()
        list = list.split(",")
        
        #remove blank lines
        for each in list[:]:
            if each == "":
                list.remove(each)
    
    sql_attacks = get_sql_attacks()
    malwares = get_malwares()
    brute_force_attacks = get_brute_force_attacks()
        
    
    return render_template("index.html", logs=logs, alerts=alerts, list=list, sql_attacks=sql_attacks, malwares=malwares, brute_force_attacks=brute_force_attacks)



@app.route('/data')
def data():

    with open("log.txt","r") as file:
        logs = file.read().split("\n")
        logs = [x for x in logs if x != ""]
        logs = logs[-10:]

    with open("alerts.txt","r") as file:
        alerts = file.read().split("\n")
        alerts = [x for x in alerts if x != ""]
        alerts = alerts[-10:]

    with open("ip.txt","r") as file:
        ip_list = file.read().split(",")
        ip_list = [x for x in ip_list if x != ""]

    return jsonify({
        "logs": logs,
        "alerts": alerts,
        "ips": ip_list
    })



def process_new_logs():
    global sql_attacks, malwares, brute_force_attacks
    new_sql = 0
    new_malware = 0
    new_brute = 0


    new_sql += 1 

    sql_attacks += new_sql
    malwares += new_malware
    brute_force_attacks += new_brute

if __name__ == "__main__":
    app.run(debug=True)