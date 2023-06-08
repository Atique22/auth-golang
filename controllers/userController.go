package controllers

import (
	"github.com/atique/auth-golang/database"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/mongo"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "users")
var validate = validator.New()

func Signup() {

}
func Login() {

}
func HashPassword() {

}
func VerifyPassword() {

}

func GetUsers() {

}

func GetUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userId := c.Param("user_id")
	}
}
