package main

import (
	"flag"
	"io/ioutil"
	"log"

	"github.com/Mind-Informatica-srl/idcrypt/pkg/otp"
)

var (
	secret string
	check  string
)

func main() {
	flag.StringVar(&secret, "secret", "LMT4URYNZKEWZRAA", "The OTP secret")
	flag.StringVar(&check, "check", "", "Check if the proposed value is good or not")
	flag.Parse()

	engine := otp.NewTOTP(secret)
	bytes, err := engine.GetQRCodeAsPNG("test.user@google.com", "test_app")
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("qr.png", bytes, 0644)
	if err != nil {
		panic(err)
	}

	log.Println("Wrote qr.png")

	if check != "" {
		status := engine.Verify(check)
		log.Printf("Check status: %v", status)
	}
}
