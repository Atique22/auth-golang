package helpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/atique/auth-golang/database"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type SignedDetails struct {
	First_name string
	Last_name  string
	Email      string
	User_type  string
	Uid        string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY string = os.Getenv("SECRET_KEY")

func GenerateAllTokens(email string, firstName string, lastName string, userType string, uid string) (signedToken string, signedRefreshToken string, err error) {
	claims := &SignedDetails{
		Email:      email,
		First_name: firstName,
		Last_name:  lastName,
		Uid:        uid,
		User_type:  userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(24)).Unix(),
		},
	}
	refreshClaims := &SignedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(168)).Unix(),
		},
	}
	// secretKey := []byte(SECRET_KEY)
	// token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(secretKey)
	// refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims).SignedString(secretKey)
	// Generate the elliptic curve private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Panic(err)
		return "", "", err
	}

	// Sign the tokens using the private key
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(privateKey)
	if err != nil {
		log.Panic(err)
		return "", "", err
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims).SignedString(privateKey)
	if err != nil {
		log.Panic(err)
		return "", "", err
	}

	// if err != nil {
	// 	log.Panic(err)
	// 	return
	// }
	return token, refreshToken, err
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

	var updateObj primitive.D
	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})
	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOptions{
		Upsert: &upsert,
	}

	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{
			{"$set", updateObj},
		},
		&opt,
	)

	defer cancel()

	if err != nil {
		log.Panic(err)
		return
	}
	return

}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {

	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			// Replace "SECRET_KEY" with your actual secret key value or retrieve it from the environment
			secretKey := []byte("SECRET_KEY")
			return secretKey, nil
		},
	)

	if err != nil {
		msg = err.Error()
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		msg = fmt.Sprintf("the token is invalid")
		msg = err.Error()
		return
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		msg = fmt.Sprintf("token is expired")
		msg = err.Error()
		return
	}
	return claims, msg
}
