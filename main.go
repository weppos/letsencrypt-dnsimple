package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/dnsimple"
)

// Create a user. New accounts need an email and private key to start.
const rsaKeySize = 2048

// You'll need a user or account type that implements acme.User
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

var (
	dnsimpleEmail  string
	dnsimpleApiKey string
	acmeUrl        string
	email          string
	dataPath       string
)

func usage() {
	bin := path.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", bin)
	fmt.Fprintf(os.Stderr, "\t%s [flags] domain\n", bin)
	fmt.Fprintf(os.Stderr, "\t%s [flags] domain1,domainN\n", bin)
	fmt.Fprintf(os.Stderr, "Flags:\n")
	flag.PrintDefaults()
}

func init() {
	flag.StringVar(&dnsimpleEmail, "user", "", "DNSimple user email")
	flag.StringVar(&dnsimpleApiKey, "api-key", "", "DNSimple API key")
	flag.StringVar(&acmeUrl, "url", "https://acme-staging.api.letsencrypt.org/", "The CA URL")
	flag.StringVar(&email, "email", "", "Email used for registration and recovery contact")
	flag.StringVar(&dataPath, "path", ".data", "Directory to use for storing the data")
	flag.Usage = usage
	flag.Parse()
}

func main() {
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if email == "" {
		fmt.Println("--email is required")
		os.Exit(2)
	}

	now := time.Now().Unix()
	domains := strings.Split(flag.Args()[0], ",")

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}

	if r, _ := regexp.Compile("%v"); r.MatchString(email) {
		email = fmt.Sprintf(email, now)
	}
	user := User{
		Email: email,
		key:   privateKey,
	}

	usersPath := fmt.Sprintf("%v/users/%v", dataPath, user.GetEmail())
	log.Println(usersPath)

	fileWrite(usersPath, "privkey.pem", pemEncode(privateKey))
	fileWrite(usersPath, "pubkey.pem", pemEncode(privateKey.Public()))

	// log: user
	log.Println(user)

	// A client facilitates communication with the CA server.
	client, err := acme.NewClient(strings.Join([]string{acmeUrl, "directory"}, "/"), &user, acme.RSA2048)
	if err != nil {
		log.Fatal(err)
	}

	// Force to use DNSimple
	provider, err := dnsimple.NewDNSProviderCredentials(dnsimpleEmail, dnsimpleApiKey)
	if err != nil {
		log.Fatal(err)
	}

	client.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})
	client.SetChallengeProvider(acme.DNS01, provider)
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register; be sure to save it
	reg, err := client.Register()
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg

	// log: registration
	log.Println(reg)

	// The client has a URL to the current Let's Encrypt Subscriber Agreement.
	// The user will need to agree to it.
	err = client.AgreeToTOS()
	if err != nil {
		log.Fatal(err)
	}

	// The acme library takes care of completing the challenges to obtain the certificate(s).
	bundle := true
	certificates, failures := client.ObtainCertificate(domains, bundle, nil, false)
	if len(failures) > 0 {
		log.Fatal(failures)
	}

	// log: certificate
	log.Println(fmt.Printf("[INFO][%s] Certificate %s", certificates.CertURL, strings.Join(domains, ", ")))

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. This is where you should save them to files!
	//fmt.Printf("%#v\n", certificates)

	certsPath := fmt.Sprintf("%v/certs/%v", dataPath, now)
	log.Println(certsPath)
	fileWrite(certsPath, "privkey.pem", certificates.PrivateKey)
	fileWrite(certsPath, "fullchain.pem", certificates.Certificate)

	log.Println("completed!")
}

func mkPath(path string) {
	if err := os.MkdirAll(path, 0755); err != nil {
		log.Fatal(err)
	}
}

func fileWrite(path, filename string, data []byte) {
	filepath := fmt.Sprintf("%s/%s", path, filename)
	mkPath(path)

	if err := ioutil.WriteFile(filepath, data, 0644); err != nil {
		log.Fatal(err)
	}
}

func pemEncode(data interface{}) []byte {
	var pemBlock *pem.Block
	switch key := data.(type) {
	case *rsa.PrivateKey:
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		break
	case *rsa.PublicKey:
		bytes, _ := x509.MarshalPKIXPublicKey(key)
		pemBlock = &pem.Block{Type: "RSA PUBLIC KEY", Bytes: bytes}
		break
	}

	return pem.EncodeToMemory(pemBlock)
}
