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
  -p12
        Convert certificate and key to PKCS#12 format
  -p12file string
        PKCS#12 file (default "certfile.p12")
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

[Linux](https://github.com/abiiranathan/gencert/releases/download/v0.1.1/gencert)

[Windows](https://github.com/abiiranathan/gencert/releases/download/v0.1.1/gencert.exe)

Convert .crt to .p12

```bash
openssl pkcs12 -export -out certificate.p12 -inkey keyfile.key -in certfile.crt
```

Or use `gencert` to generate a .p12 file.

```bash
gencert -hosts "localhost,192.168.43.222" -org "Yo Medical Files(U) Ltd" -cert "certfile.crt" -key "keyfile.key" -root-ca "rootCA.crt" -root-ca-key "rootCA.key"
```

This will generate .crt and .key files for the given hostnames and IPs.
It will also generate a root CA certificate and key file.
Now you can convert the .crt and .key files to .p12 file.

```bash
gencert -p12 -p12file "certificate.p12" -cert "certfile.crt" -key "keyfile.key"
```
