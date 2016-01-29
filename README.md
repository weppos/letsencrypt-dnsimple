# letsencrypt-dnsimple

This is a super-simple [Go](https://golang.org/) script to request an SSL certificate via [Let's Encrypt](https://letsencrypt.org/) for a domain hosted at [DNSimple](https://dnsimple.com/).

## Usage

**DNSimple environment variables**

```shell
export DNSIMPLE_EMAIL="example@example.com"
export DNSIMPLE_API_TOKEN="1234567890"
$ go run main.go domain1,domain2,domainN
```

**Explicit DNSimple parameters**

```shell
$ go run main.go \
        --user "example@example.com" \
        --api-key "1234567890" \
         domain1,domain2,domainN
```

**Example**

```shell
$ go run main.go \
        --user "example@example.com" \
        --api-key "1234567890" \
        simonecarletti.com,www.simonecarletti.com
```
