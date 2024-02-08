all: linux windows

linux:
	go build -ldflags="-s -w"

windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"

clean:
	rm -rf *.crt *.key *.pem *.csr gencert

.PHONY: all clean