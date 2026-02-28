import time
import threading

#this function collects data from logfile and writes into log.txt
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
                f.flush()


#simultaneously read access.log and auth.log and pass to monitor function
t1 = threading.Thread(target=monitor, args=("/var/log/auth.log",))
t2 = threading.Thread(target=monitor, args=("/var/log/access.log",))

#start thread
t1.start()
t2.start()

#pause main program until the thread finishes
t1.join()
t2.join()