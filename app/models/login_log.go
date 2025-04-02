package models

import (
	revmongo "github.com/QFO6/rev-mongo/v2"

	"go.mongodb.org/mongo-driver/bson"
)

type LoginLog struct {
	revmongo.BaseModel `bson:",inline"`
	Account            string `bson:"Account,omitempty"`
	Status             string `bson:"Status,omitempty"`
	IPAddress          string `bson:"IPAddress,omitempty"`
	User               *User  `bson:"-"`
}

func (m *LoginLog) GenUser() {
	user := new(User)
	do := revmongo.New(user)
	do.Query = bson.M{"Identity": m.Account}
	do.GetByQ()
	m.User = user
}
