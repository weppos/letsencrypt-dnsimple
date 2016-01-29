# letsencrypt-dnsimple

This is a super-simple [Go](https://golang.org/) script to request an SSL certificate via [Let's Encrypt](https://letsencrypt.org/) for a domain hosted at [DNSimple](https://dnsimple.com/).

## Usage

```shell
export DNSIMPLE_EMAIL="example@example.com"
export DNSIMPLE_API_TOKEN="1234567890"
$ go run main.go domain1[,domain2,domainN]
```

**Example**

```shell
export DNSIMPLE_EMAIL="example@example.com"
export DNSIMPLE_API_TOKEN="1234567890"
$ go run main.go simonecarletti.com,www.simonecarletti.com
```
