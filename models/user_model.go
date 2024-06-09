package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `json:"id" bson:"_id"`
	UserId       string             `json:"user_id" bson:"user_id"`
	FirstName    *string            `json:"first_name" bson:"first_name" validate:"required,min=2,max=100"`
	LastName     *string            `json:"last_name" bson:"last_name" validate:"required,min=2,max=100"`
	Password     *string            `json:"password" bson:"password" validate:"required,min=6"`
	Email        *string            `json:"email" bson:"email" validate:"required,min=2,max=100"`
	Phone        *string            `json:"phone" bson:"phone" validate:"required,min=10,max=10"`
	Token        *string            `json:"token" bson:"token"`
	UserType     *string            `json:"user_type" bson:"user_type" validate:"required,eq=ADMIN|eq=USER"`
	RefreshToken *string            `json:"refresh_token" bson:"refresh_token"`
	CreatedAt    time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at" bson:"updated_at"`
}
