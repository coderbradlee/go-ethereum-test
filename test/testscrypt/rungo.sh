export GOROOT=/usr/local/go
export GOPATH=/root/gopath
export GOBIN=/root/gopath/bin

#rm -fr testscypt
go build -o testscypt ./testgo
./testscypt
