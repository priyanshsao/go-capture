# installing the libpcap for ubuntu
sudo apt-get install libpcap-dev
# installing all the required libraries
go mod tidy
# running the program
go run capture.go google.com
# printing the instructions
echo "[Program success]: to run with custom host run main file(capture.go) with host name and open a new terminal and make http request to it."
echo "[Example]: "custom host: xyz.com\n[cmd]: go run capture.go xyz.com\n[cmd(new terminal)]: curl https://xyz.com"
