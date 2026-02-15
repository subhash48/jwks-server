package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

type JWK struct {
	KTY string `json:"kty"`
	USE string `json:"use,omitempty"`
	ALG string `json:"alg,omitempty"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

// FromRSAPublicKey converts RSA public key into a JWK using base64url (no padding).
func FromRSAPublicKey(kid string, pub *rsa.PublicKey) JWK {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	return JWK{
		KTY: "RSA",
		USE: "sig",
		ALG: "RS256",
		KID: kid,
		N:   n,
		E:   e,
	}
}

