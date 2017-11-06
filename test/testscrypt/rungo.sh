export GOROOT=/usr/lib/golang
export GOPATH=/root/gopath
export GOBIN=/root/gopath/bin

rm -fr testscypt
go build -o testscypt testgo
./testscypt
