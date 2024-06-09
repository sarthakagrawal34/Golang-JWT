package controllers

import (
	"context"
	"fmt"
	"golang-jwt/database"
	"golang-jwt/helpers"
	"golang-jwt/models"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.MongoClient, "user")
var validate = validator.New()

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = "password is incorrect"
		check = false
	}
	return check, msg
}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var user models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationError := validate.Struct(user)
		if validationError != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationError.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		count1, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the email"})
		}
		defer cancel()

		password, err := HashPassword(*user.Password)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while hashing the password"})
			return
		}
		user.Password = &password

		count2, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while checking for the phone"})
		}
		defer cancel()

		if count1 > 0 || count2 > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This email or phone is already registered"})
			return
		}

		user.CreatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.UpdatedAt, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.UserId = user.ID.Hex()
		token, refreshToken, err := helpers.GenerateAllTokens(*user.Email, *user.FirstName, *user.LastName, *user.UserType, user.UserId)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating the tokens"})
		}
		user.Token = &token
		user.RefreshToken = &refreshToken

		result, err := userCollection.InsertOne(ctx, user)
		var msg string
		if err != nil {
			msg = fmt.Sprintf("User item was not created due to this error: %v", err.Error())
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()

		msg = fmt.Sprintf("User is inserted successfully with the insertion number as: %v", result)
		c.JSON(http.StatusOK, gin.H{"message": msg})
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "email is incorrect"})
			return
		}

		isValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if !isValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}
		token, refreshToken, err := helpers.GenerateAllTokens(*foundUser.Email, *foundUser.FirstName, *foundUser.LastName, *foundUser.UserType, foundUser.UserId)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while generating the tokens"})
			return
		}
		helpers.UpdateAllTokens(token, refreshToken, foundUser.UserId)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.UserId}).Decode(&foundUser)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetAllUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := helpers.CheckUserType(c, "ADMIN"); err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err := strconv.Atoi(c.Query("limit"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}
		pageNumber, err1 := strconv.Atoi(c.Query("page"))
		if err1 != nil || pageNumber < 1 {
			pageNumber = 1
		}

		startIndex := (pageNumber - 1) * recordPerPage

		matchStage := bson.D{{Key: "$match", Value: bson.D{{}}}}
		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: bson.D{{Key: "_id", Value: "null"}}},
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
		}
		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, groupStage, projectStage,
		})
		defer cancel()

		if err != nil {
			log.Panic("Error in aggregate function: ", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "error occurred while listing user items"})
			return
		}
		var allUsers []bson.M
		if err = result.All(ctx, &allUsers); err != nil {
			log.Fatal("Error in decoding all users function: ", err)
		}
		c.JSON(http.StatusOK, allUsers)
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userId := c.Param("user_id")

		if err := helpers.MatchUserTypeToUid(c, userId); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Return the response
		c.JSON(http.StatusOK, user)
	}
}
