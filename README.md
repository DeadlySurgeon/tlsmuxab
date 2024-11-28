# TLS Mux AB

Cert Experiment

## Generate Certificates for testing

From base directory:

```
go run
```

## Curl

```bash
curl \
--cert certs/clients/leo-cert.pem \
--key certs/clients/leo-key.pem \
--cacert certs/ca/intermediate-ca-cert.pem \
--connect-to ::127.0.0.1:9900 https://beta
```

## OpenSSL Check

```sh
openssl s_client -connect localhost:9901 -CAfile certs/ca/root-ca-cert.pem
```
