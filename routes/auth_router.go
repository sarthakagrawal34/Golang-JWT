package routes

import (
	"golang-jwt/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(in *gin.Engine){
	in.POST("/users/signup", controllers.SignUp())
	in.POST("/users/login", controllers.Login())
}
