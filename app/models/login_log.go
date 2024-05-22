package models

import (
	revmongo "github.com/QFO6/rev-mongo"
	mgo "github.com/globalsign/mgo"

	"github.com/globalsign/mgo/bson"
)

type LoginLog struct {
	revmongo.BaseModel `bson:",inline"`
	Account            string `bson:"Account,omitempty"`
	Status             string `bson:"Status,omitempty"`
	IPAddress          string `bson:"IPAddress,omitempty"`
	User               *User  `bson:"-"`
}

func (m *LoginLog) GenUser(s *mgo.Session) {
	user := new(User)
	do := revmongo.New(s, user)
	do.Query = bson.M{"Identity": m.Account}
	do.GetByQ()
	m.User = user
}
