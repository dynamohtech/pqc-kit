// Sample code for pqc-kit tests. Not meant to be run.
package svc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"

	"github.com/golang-jwt/jwt/v5"
)

const keyBits = 1024

func NewKeys() (*cryptorsa.PrivateKey, *ecdsa.PrivateKey, error) {
	rk, err := cryptorsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, err
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return rk, ek, err
}

func Sign(k *cryptorsa.PrivateKey, digest []byte) ([]byte, error) {
	return cryptorsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest)
}

func Checksum(b []byte) [16]byte { return md5.Sum(b) }

func Legacy(b []byte) [20]byte { return sha1.Sum(b) }

func Mac(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func PostQuantum() (*mlkem.DecapsulationKey768, error) { return mlkem.GenerateKey768() }

func ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

var certAlg = x509.SHA1WithRSA

var signer = jwt.SigningMethodES256
