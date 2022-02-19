// Copyright 2022 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// represents data about a tag.
type tag struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// tags slice to seed tag data.
var tags = []tag{
	{ID: "1", Name: "Blue"},
	{ID: "2", Name: "Red"},
	{ID: "3", Name: "Green"},
}

func Verifier() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Request.Header.Get("X-Firebase-AppCheck")
		appId, err := VerifyToken(token, c)
		if err != nil {
			log.Printf("error verifying token.\nError: %s", err.Error())
			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
			return
		}
		c.Set("APP_ID", appId)
		c.Next()
	}
}

func VerifyToken(token string, c *gin.Context) (string, error) {
	if token == "" {
		return "", errors.New("no token found")
	}

	// Obtain the Firebase App Check Public Keys
	// Note: It is not recommended to hard code these keys as they rotate,
	// but you should cache them for up to 6 hours.
	jwksURL := "https://firebaseappcheck.googleapis.com/v1beta/jwks"

	options := keyfunc.Options{
		Ctx: c,
		RefreshErrorHandler: func(err error) {
			log.Printf("there was an error with the jwt.Keyfunc\nError: %s", err.Error())
		},
		RefreshInterval: time.Hour * 6,
	}

	jwks, err := keyfunc.Get(jwksURL, options)
	if err != nil {
		return "", errors.New("failed to create JWKS from resource at the given URL. " + err.Error())
	}

	// Verify the signature on the App Check token
	// Ensure the token is not expired
	payload, err := jwt.Parse(token, jwks.Keyfunc)
	if err != nil {
		return "", errors.New("failed to parse token. " + err.Error())
	}

	if !payload.Valid {
		return "", errors.New("invalid token")
	} else if payload.Header["alg"] != "RS256" {
		// Ensure the token's header uses the algorithm RS256
		return "", errors.New("invalid algorithm")
	} else if payload.Header["typ"] != "JWT" {
		// Ensure the token's header has type JWT
		return "", errors.New("invalid type")
	} else if !verifyAudClaim(payload.Claims.(jwt.MapClaims)["aud"].([]interface{})) {
		// Ensure the token's audience matches your project
		return "", errors.New("invalid audience")
	} else if !strings.Contains(payload.Claims.(jwt.MapClaims)["iss"].(string),
		"https://firebaseappcheck.googleapis.com/"+os.Getenv("PROJECT_NUMBER")) {
		// Ensure the token is issued by App Check
		return "", errors.New("invalid issuer")
	}
	log.Println("the token is valid")
	jwks.EndBackground()

	// The token's subject will be the app ID, you may optionally filter against
	// an allow list
	return payload.Claims.(jwt.MapClaims)["sub"].(string), nil
}

func verifyAudClaim(auds []interface{}) bool {
	for _, aud := range auds {
		if aud == "projects/"+os.Getenv("PROJECT_NUMBER") {
			return true
		}
	}
	return false
}

func main() {
	router := gin.Default()
	router.Use(Verifier())

	router.GET("/", getTags)

	router.Run("localhost:8080")
}

// getTags responds with the list of all tags as JSON.
func getTags(c *gin.Context) {
	appId := c.GetString("APP_ID")
	c.IndentedJSON(http.StatusOK, gin.H{"data": tags, "app": appId})
}
