# certificate-transparency-tools
Tools to interact with a certificate transparency server This repository contains python scripts to dump a certificate transparency
server.

## Usage

This will download all certificates from the server https://ct1.digicert-ct.com/log to out/digicert-X.der

```
mkdir out
python download_all_certs.py https://ct1.digicert-ct.com/log out/digicert-
```

## Notes

No cryptographic verification is done, except for checking the certificate of
the server for the https connection.
