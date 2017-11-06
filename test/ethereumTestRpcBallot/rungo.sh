export GOROOT=/usr/lib/golang
export GOPATH=/root/gopath
export GOBIN=/root/gopath/bin

rm -fr ballot
go build -o ballot testgo
./ballot
