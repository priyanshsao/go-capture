# installing the libpcap for ubuntu
sudo apt-get install libpcap-dev
# go module setup
go mod init "github.com/go-capture"
# installing all the required libraries
go mod tidy
# running the program
go run capture.go google.com
