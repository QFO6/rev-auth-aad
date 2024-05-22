package models

import (
	revmongo "github.com/QFO6/rev-mongo"
)

type Profile struct {
	revmongo.BaseModel `bson:",inline"`
	Identity           string `bson:"Identity,omitempty" form:",required,input,Enterprise ID"`
	Mail               string `bson:"Mail,omitempty"`
	IsAdmin            string `bson:"IsAdmin,omitempty" form:",,radio"`
	IsDeveloper        string `bson:"IsDeveloper,omitempty" form:",,radio"`
	UserName           string `bson:"UserName,omitempty"`
	User               *User  `bson:"-"`
}
