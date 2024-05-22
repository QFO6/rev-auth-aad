package controllers

import (
	"fmt"
	"strings"
	"time"

	revauthaad "github.com/QFO6/rev-auth-aad"
	revauthaadmodels "github.com/QFO6/rev-auth-aad/app/models"
	revmongo "github.com/QFO6/rev-mongo"
	utilsgo "github.com/QFO6/utils-go"

	"github.com/globalsign/mgo/bson"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type Auth struct {
	*revel.Controller
	revmongo.MgoController
}

// Authenticate with AAD, act as a daemon API, suport users without enable MFA.
// For Daemon refer: https://learn.microsoft.com/en-us/azure/active-directory/develop/scenario-daemon-overview
func (c *Auth) Authenticate(account, password string) revel.Result {
	//get nextUrl
	nextUrl := c.Params.Get("nextUrl")
	if nextUrl == "" {
		nextUrl = "/"
	}

	if account == "" || password == "" {
		c.Flash.Error("Please fill in account and password")
		return c.Redirect(c.Request.Referer())
	}

	//save current user information
	currentUser := new(revauthaadmodels.User)
	loginLog := new(revauthaadmodels.LoginLog)
	loginLog.Status = "SUCCESS"
	loginLog.IPAddress = c.Request.RemoteAddr
	currentUserIdentidy := strings.ToLower(account)
	e2eTestUser := revel.Config.StringDefault("e2e.test.login.account", "")
	if account == e2eTestUser {
		currentUser.Identity = currentUserIdentidy
		fmt.Printf("Login the test account: %v", currentUserIdentidy)
	} else {
		authUser := revauthaad.AuthenticatePublicClient(account, password)
		currentUserIdentidy = strings.ToLower(authUser.Account)

		loginLog.Account = currentUserIdentidy
		if !authUser.IsAuthenticated {
			loginLog.Status = "FAILURE"
			revmongo.New(c.MgoSession, loginLog).Create()

			c.Flash.Error("Authenticate failed with error: %v", authUser.Error)
			return c.Redirect(c.Request.Referer())
		}

		currentUser.Identity = currentUserIdentidy
		currentUser.Mail = authUser.Email
		currentUser.Avatar = authUser.Avatar
		currentUser.Name = authUser.Name
		currentUser.Depart = authUser.Depart
		currentUser.First = authUser.First
		currentUser.Last = authUser.Last
		// save authorized user information to db by calling SaveUser defined in revauthaad
		go func(user *revauthaadmodels.User) {
			// save to local user
			s := revmongo.NewMgoSession()
			defer s.Close()
			err := user.SaveUser(s)
			if err != nil {
				revel.AppLog.Errorf("Save user error: %v", err)
			}

		}(currentUser)
	}

	revmongo.New(c.MgoSession, loginLog).Create()

	c.Session["UserName"] = strings.TrimSpace(currentUser.Name)
	c.Session["Email"] = strings.TrimSpace(strings.ToLower(currentUser.Mail))
	c.Session["Identity"] = strings.TrimSpace(strings.ToLower(currentUserIdentidy))
	go cache.Set(c.Session.ID(), currentUser, cache.DefaultExpiryTime)

	c.Flash.Success("Welcome, %v", currentUser.Name)
	return c.Redirect(nextUrl)
}

// Logout
func (c *Auth) Logout() revel.Result {
	if revauthaad.AzureADTenantAuthority == "" || strings.TrimSpace(revauthaad.AzureADTenantAuthority) == "" {
		c.Flash.Error("No Azure AD tenant authority found, please contact with system administrator.")
		return c.Redirect(c.Request.Referer())
	}
	if revauthaad.AzureADAppPostLogoutRedirectUri == "" || strings.TrimSpace(revauthaad.AzureADAppPostLogoutRedirectUri) == "" {
		c.Flash.Error("No application logout redirect url found, please contact with system administrator.")
		return c.Redirect(c.Request.Referer())
	}

	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())
	c.Session = make(map[string]interface{})

	/**
	 * Construct a logout URI and redirect the user to end the
	 * session with Azure AD. For more information, visit:
	 * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
	 */
	logoutUri := fmt.Sprintf("%s/oauth2/v2.0/logout?post_logout_redirect_uri=%s", revauthaad.AzureADTenantAuthority, revauthaad.AzureADAppPostLogoutRedirectUri)

	c.Flash.Success("You have logged out.")
	return c.Redirect(logoutUri)
}

// Checks if the session expired by checking if the user identity is still present
func (c *Auth) CheckLogin() revel.Result {
	res := utilsgo.Response{
		Code:    utilsgo.OK,
		Message: utilsgo.StatusText(utilsgo.OK),
	}
	identity, err := c.Session.Get("Identity")
	fmt.Printf("Time:%s; Identity:%s", time.Now().Format(time.RFC3339), identity)
	if err != nil {
		fmt.Println("Session expired")
		res.Code = utilsgo.SESSION_EXPIRED
		res.Message = utilsgo.StatusText(utilsgo.SESSION_EXPIRED)
		return c.RenderJSON(res)
	}

	user := new(revauthaadmodels.User)

	// get user information from cache by using the session ID retrieved from the cookie
	if err := cache.Get(c.Session.ID(), &user); err != nil {
		fmt.Println("user not found in cache")

		do := revmongo.New(c.MgoSession, user)
		do.Query = bson.M{"Identity": identity.(string)}

		if err := do.GetByQ(); err != nil {
			fmt.Println("no matched account found in db")
			res.Code = utilsgo.LOGIN_FAILED
			res.Message = utilsgo.StatusText(utilsgo.LOGIN_FAILED)
			return c.RenderJSON(res)
		}

		// set the user information in cache
		go cache.Set(c.Session.ID(), user, cache.DefaultExpiryTime)
	}

	c.Session["IsAdmin"] = user.IsAdmin
	res.Data = user
	return c.RenderJSON(res)
}
