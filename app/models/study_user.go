package models

import (
	revmongo "github.com/QFO6/rev-mongo"
)

type StudyUser struct {
	revmongo.BaseModel `bson:",inline"`
	StudyCode          string `bson:"StudyCode,omitempty" form:",required,select"`
	Identity           string `bson:"Identity,omitempty" form:",required,input,Enterprise ID"`
	Mail               string `bson:"Mail,omitempty"`
	RoleName           string `bson:"RoleName,omitempty" form:",required,select"`
	IsApprover         string `bson:"IsApprover,omitempty" form:",,radio"` // who can approve access
	IsGuest            string `bson:"IsGuest,omitempty" form:",,radio"`    // who only have view access
	UserName           string `bson:"UserName,omitempty"`                  // copy from User.Name
	User               *User  `bson:"-"`
	AccessToken        string `bson:"-"`
}
