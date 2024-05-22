package controllers

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/revel/revel"

	revauthaad "github.com/QFO6/rev-auth-aad"
	utilsgo "github.com/QFO6/utils-go"
)

// VerifyAadToken to veriry Azure AD token
func VerifyAadToken(bearerToken, tokenKeysUrl string) (*jwt.Token, error) {
	if bearerToken == "" {
		return nil, fmt.Errorf("no valid Azure AD token provided")
	}

	if tokenKeysUrl == "" {
		return nil, fmt.Errorf("no valid Azure AD token keys url provided")
	}

	if revauthaad.AzureADTenantId == "" {
		return nil, fmt.Errorf("no valid tenant id, please set it during deployment")
	}

	if revauthaad.AzureADAppClientId == "" {
		return nil, fmt.Errorf("no valid application client id, please set it during deployment")
	}

	keySet, err := jwk.Fetch(context.Background(), tokenKeysUrl)
	if err != nil {
		log.Printf("Failed to fetch keys from microsoft: %v", err)
		return nil, err
	}

	parsedToken, err := jwt.Parse(bearerToken, func(jwtToken *jwt.Token) (interface{}, error) {
		if jwtToken.Method.Alg() != jwa.RS256.String() {
			return nil, fmt.Errorf("unexpected signing method: %v", jwtToken.Header["alg"])
		}
		kid, ok := jwtToken.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		keys, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}

		publickey := &rsa.PublicKey{}
		err = keys.Raw(publickey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}

		return publickey, nil
	})

	if err != nil {
		return nil, err
	}

	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		if tid, found := claims["tid"].(string); found && tid == revauthaad.AzureADTenantId {
			if claims.VerifyAudience(revauthaad.AzureADAppClientId, true) {
				return parsedToken, nil
			} else {
				return nil, fmt.Errorf("token is not for current application")
			}
		} else {
			return nil, fmt.Errorf("token is not for current tenant")
		}
	} else {
		return nil, fmt.Errorf("invalid claims")
	}
}

// GetBearerToken get bearer token from request headers
func GetBearerToken(request *revel.Request) string {
	bearerTokenString := request.Header.Get("Authorization")
	if !utilsgo.IsValidString(bearerTokenString) {
		log.Printf("No bearer token found")
		return ""
	}

	tempArrs := strings.Split(bearerTokenString, "Bearer ")
	if len(tempArrs) != 2 {
		log.Printf("Invalid bearer token")
		return ""
	}

	return strings.TrimSpace(tempArrs[1])
}
