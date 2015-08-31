# certificate-transparency-tools
Tools to interact with a certificate transparency server This repository contains python scripts to dump a certificate transparency
server.

## Usage

This will download all certificates from the server https://ct1.digicert-ct.com/log to out/digicert-X.der

```
mkdir out
python download_all_certs.py https://ct1.digicert-ct.com/log out/digicert-
```

To extract the names from the pre-certificates, do:
```
find out/ -name "digicert*precert*"  | xargs -n 8000 python get_precert_cn.py  | sort -u > all-digicert-pre-certificate-names-sorted.txt
```

## Notes

No cryptographic verification is done, except for checking the certificate of
the server for the https connection.

You can start the process again and it will download only new certificates.
