package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
)

// Create a user. New accounts need an email and private key to start.
const rsaKeySize = 2048

// You'll need a user or account type that implements acme.User
type User struct {
	Email        string
	Registration *acme.RegistrationResource
	key          *rsa.PrivateKey
}

func (u User) GetEmail() string {
	return u.Email
}
func (u User) GetRegistration() *acme.RegistrationResource {
	return u.Registration
}
func (u User) GetPrivateKey() *rsa.PrivateKey {
	return u.key
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s domain1,domain2,domainN", os.Args[0])
	flag.PrintDefaults()
}

var (
	dnsimpleEmail  string
	dnsimpleApiKey string
	acmeUrl        string
	email          string
	path           string
)

func init() {
	flag.StringVar(&dnsimpleEmail, "user", "", "DNSimple user email")
	flag.StringVar(&dnsimpleApiKey, "api-key", "", "DNSimple API key")
	flag.StringVar(&acmeUrl, "url", "https://acme-staging.api.letsencrypt.org/", "The CA URL")
	flag.StringVar(&email, "email", "", "Email used for registration and recovery contact")
	flag.StringVar(&path, "path", ".data", "Directory to use for storing the data")
	flag.Parse()
}

func main() {
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if email == "" {
		fmt.Println("--email is required")
		os.Exit(2)
	}

	domains := strings.Split(flag.Args()[0], ",")
	now := time.Now().Unix()

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}

	email = fmt.Sprintf(email, now)
	user := User{
		Email: email,
		key:   privateKey,
	}

	usersPath := fmt.Sprintf("%v/users/%v", path, user.GetEmail())
	log.Println(usersPath)

	fileWrite(usersPath, "privkey.pem", pemEncode(user.GetPrivateKey()))
	fileWrite(usersPath, "pubkey.pem", pemEncode(user.GetPrivateKey().Public()))

	// log: user
	log.Println(user)

	// A client facilitates communication with the CA server.
	client, err := acme.NewClient(strings.Join([]string{acmeUrl, "directory"}, "/"), &user, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}

	// Force to use DNSimple
	provider, err := acme.NewDNSProviderDNSimple(dnsimpleEmail, dnsimpleApiKey)
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
	certificates, failures := client.ObtainCertificate(domains, bundle, nil)
	if len(failures) > 0 {
		log.Fatal(failures)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. This is where you should save them to files!
	//fmt.Printf("%#v\n", certificates)

	certsPath := fmt.Sprintf("%v/certs/%v", path, now)
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
