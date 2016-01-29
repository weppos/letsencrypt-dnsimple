package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"io/ioutil"

	"github.com/xenolf/lego/acme"
)

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

// Create a user. New accounts need an email and private key to start.
const rsaKeySize = 2048

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Missing args")
	}
	domains := strings.Split(os.Args[1], ",")
	now := time.Now().Unix()

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}

	User := User{
		Email: fmt.Sprintf("weppos+lego-%v@gmail.com", now),
		key:   privateKey,
	}

	// log: user
	log.Println(User)

	// A client facilitates communication with the CA server.
	client, err := acme.NewClient("https://acme-staging.api.letsencrypt.org/directory", &User, rsaKeySize)
	if err != nil {
		log.Fatal(err)
	}

	// Force to use DNSimple
	provider, err := acme.NewDNSProviderDNSimple("", "")
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
	User.Registration = reg

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

	certsPath := fmt.Sprintf(".certs/%v", now)
	err = os.MkdirAll(certsPath, 0755)
	if err != nil {
		log.Fatal(err)
	}

	keyFile := fmt.Sprintf("%v/privkey.pem", certsPath)
	err = ioutil.WriteFile(keyFile, certificates.PrivateKey, 0644)
	if err != nil {
		log.Fatal(err)
	}

	certFile := fmt.Sprintf("%v/fullchain.pem", certsPath)
	err = ioutil.WriteFile(certFile, certificates.Certificate, 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("completed!")
	log.Println(certsPath)
}
