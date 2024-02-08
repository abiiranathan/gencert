# gencert

Self-signed certificate generator for development purposes or LAN-based usage.

## Usage

```bash
gencert -h
```

```bash
Usage of ./gencert:
  -cert string
        Certificate file (default "certfile.crt")
  -days int
        Duration that certificate is valid for, in days (default 365)
  -hosts string
        Comma-separated hostnames and IPs to generate a certificate for (default "localhost")
  -key string
        Private key file (default "keyfile.key")
  -org string
        Organization name (default "Yo Medical Files(U) Ltd")
  -root-ca string
        Root CA certificate file (default "rootCA.crt")
  -root-ca-key string
        Root CA private key file (default "rootCA.key")
```

Gencert generates a self-signed certificate for the given hostnames and IPs.

```bash
gencert -hosts "localhost,192.168.1.43" -org "Yo Medical Files(U) Ltd"
```

This will generate a certificate and key file for the given hostnames and IPs.
It will also generate a root CA certificate and key file.

**You must install the root CA certificate in your browser and/or system to trust the
generated certificate.**

## Installation

```bash
go install github.com/abiiranathan/gencert
```

Download the latest 64-bit release from Github releases.

[Linux](https://github.com/abiiranathan/gencert/releases/download/v0.1.0/gencert)

[Windows](https://github.com/abiiranathan/gencert/releases/download/v0.1.0/gencert.exe)
