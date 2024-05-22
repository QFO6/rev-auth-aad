package controllers

import (
	"encoding/json"
	"fmt"
	"log"
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

type AppAuth struct {
	*revel.Controller
	revmongo.MgoController
}

type UserProfile struct {
	Id                       string `json:"id"`
	Mail                     string `json:"mail"`
	Avatar                   string `json:"avatar"`
	Surname                  string `json:"surname"`
	JobTitle                 string `json:"jobTitle"`
	GivenName                string `json:"givenName"`
	EmployeeId               string `json:"employeeId"`
	Department               string `json:"department"`
	DisplayName              string `json:"displayName"`
	OfficeLocation           string `json:"officeLocation"`
	PostalCode               string `json:"postalCode"`
	OnPremisesSamAccountName string `json:"onPremisesSamAccountName"`
}

func SetAzureADViewArgs(c *revel.Controller) revel.Result {
	log.Println("Setting azure AD info to view args......")
	c.ViewArgs["AzureADAppClientId"] = revauthaad.AzureADAppClientId
	c.ViewArgs["AzureADGraphApiMePath"] = revauthaad.AzureADGraphApiMePath
	c.ViewArgs["AzureADAppRedirectUri"] = revauthaad.AzureADAppRedirectUri
	c.ViewArgs["AzureADApiPublicScopes"] = revauthaad.AzureADApiPublicScopes
	c.ViewArgs["AzureADTenantAuthority"] = revauthaad.AzureADTenantAuthority
	c.ViewArgs["AppAuthLoginApiPath"] = revauthaad.AppAuthLoginApiPath
	c.ViewArgs["AzureADAppPostLogoutRedirectUri"] = revauthaad.AzureADAppPostLogoutRedirectUri
	return nil
}

// Authenticate for Azure AD, called from UI and pass userinfo in callback from AAD
// For user properties in Azure AD refer: https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0#properties
func (c *AppAuth) Authenticate(identity string) revel.Result {
	res := utilsgo.Response{
		Code:    utilsgo.OK,
		Message: utilsgo.StatusText(utilsgo.OK),
	}

	bearerToken := GetBearerToken(c.Request)
	_, err := VerifyAadToken(bearerToken, revauthaad.AzureOAuth2KeysUrl)
	if err != nil {
		log.Printf("Login failed with invalid token or error: %v", err)
		res.Code = utilsgo.PERMISSION_DENIED
		res.Message = utilsgo.StatusText(utilsgo.PERMISSION_DENIED) + fmt.Sprintf(": %v", err.Error())
		return c.RenderJSON(res)
	}

	log.Println("Authenticate for identity:", identity)
	// Only company user identity(not email) allowed
	if !utilsgo.IsValidString(identity) {
		res.Code = utilsgo.BAD_REQUEST
		res.Message = "Only company employee identity can access, please contact the administrator for help."
		return c.RenderJSON(res)
	}

	isMail := utilsgo.MAIL_REGEX.MatchString(identity)
	// Only company user identity(not email) allowed
	if isMail {
		res.Code = utilsgo.BAD_REQUEST
		res.Message = "Email is not supported, please contact the administrator for help."
		return c.RenderJSON(res)
	}

	userProfile := UserProfile{}
	currentLoginIdentifier := strings.ToLower(identity)

	loginLog := new(revauthaadmodels.LoginLog)
	loginLog.Status = "SUCCESS"
	loginLog.Account = currentLoginIdentifier
	loginLog.IPAddress = c.Request.RemoteAddr
	loginLogDo := revmongo.New(c.MgoSession, loginLog)

	e2eTestUser := strings.ToLower(revel.Config.StringDefault("e2e.test.login.account", ""))
	adminUsersStr := revel.Config.StringDefault("admin.users", "e0445226")
	adminUsers := utilsgo.RemoveBlankStrings(utilsgo.Split(strings.ToLower(adminUsersStr)))

	err = json.Unmarshal(c.Params.JSON, &userProfile)
	if err != nil {
		log.Println("Umarshal user profile failed with error: ", err)
		loginLog.Status = "FAILURE"
		loginLogDo.Create()

		res.Code = utilsgo.BAD_REQUEST
		res.Message = "Invalid user profile, please contact with system administrator."
		return c.RenderJSON(res)
	}

	saveLoginLogErr := loginLogDo.Create()
	if saveLoginLogErr != nil {
		fmt.Printf("Save login log failed with error: %v\n", saveLoginLogErr)
	}

	//save current user information
	currentUser := new(revauthaadmodels.User)
	currentUser.Identity = currentLoginIdentifier
	currentUser.Mail = userProfile.Mail
	currentUser.Avatar = userProfile.Avatar
	currentUser.Name = userProfile.DisplayName
	currentUser.Depart = userProfile.Department
	currentUser.First = userProfile.GivenName
	currentUser.Last = userProfile.Surname
	if utilsgo.StrInSlice(currentUser.Identity, adminUsers) {
		currentUser.IsAdmin = true
	}

	if identity != e2eTestUser {
		// save authorized user information to db by calling SaveUser defined in revauthaad
		go func(user *revauthaadmodels.User) {
			// save to local user
			s := revmongo.NewMgoSession()
			defer s.Close()
			err := user.SaveUser(s)
			if err != nil {
				revel.AppLog.Errorf("Save user failed with error: %v", err)
			}
		}(currentUser)
	}

	// save the user identity in the session
	// HttpOnly flag is set to true by default; Expiration is set to 24h and could be configured via session.expires
	c.Session["UserName"] = strings.TrimSpace(currentUser.Name)
	c.Session["Email"] = strings.TrimSpace(strings.ToLower(currentUser.Mail))
	c.Session["Identity"] = strings.TrimSpace(strings.ToLower(currentLoginIdentifier))
	c.Session["IsAdmin"] = currentUser.IsAdmin
	c.Session["AccessToken"] = bearerToken // for further api calls

	log.Println("Cache user information: ", currentUser)
	// cache user information by using session ID as key, DefaultExpiryTime is one hour by default
	// ID() creates a time-based UUID identifying this session
	go cache.Set(c.Session.ID(), currentUser, cache.DefaultExpiryTime)

	res.Data = currentUser

	return c.RenderJSON(res)
}

// Logout
func (c *AppAuth) Logout() revel.Result {
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

// Redirect
func (c *AppAuth) AuthRedirect() revel.Result {
	fileName := revel.BasePath + revauthaad.AppRedirectHtmlFilePath
	return c.RenderFileName(fileName, revel.Inline)
}

// Checks if the session expired by checking if the user identity is still present
func (c *AppAuth) CheckLogin() revel.Result {
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
