package revauthaad

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/QFO6/rev-auth-aad/app/models"
	"github.com/QFO6/rev-auth-aad/cache"
	utilsgo "github.com/QFO6/utils-go"

	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azauthlibgocred "github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	azauthlibgopublic "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	httpclient "github.com/QFO6/rev-auth-aad/lib/http-client"
	revmongo "github.com/QFO6/rev-mongo"
	kiotaabstractions "github.com/microsoft/kiota-abstractions-go"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphsdkme "github.com/microsoftgraph/msgraph-sdk-go/me"
	msgraphsdkmodel "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	msgraphsdkusers "github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/revel/revel"
)

var (
	AzureADAppClientId     string
	AzureADAppClientSecret string

	AzureADTenantId             = ""
	AzureADTenantAuthority      = ""
	AzureADAccountPrimaryDomain = ""
	AzureADCloudInstance        = "https://login.microsoftonline.com"

	AzureADGraphApiMePath    = "https://graph.microsoft.com/v1.0/me"
	AzureADGraphApiUsersPath = "https://graph.microsoft.com/v1.0/users"

	AzureADApiPublicScopes     = []string{"User.Read"}
	AzureADApiCredentialScopes = []string{"https://graph.microsoft.com/.default"}

	AzureADAppRedirectUri           = "/" // login redirect
	AzureADAppPostLogoutRedirectUri = "http://localhost:3000/login"

	AppAuthLoginApiPath     = "/login/v2"
	AppRedirectHtmlFilePath = "/public/lib/msal/redirect.html"

	AzureOAuth2KeysUrl = "https://login.microsoftonline.com/common/discovery/v2.0/keys"

	querySelect = []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId", "onPremisesSamAccountName", "city", "state", "country", "usageLocation"}
)

type AuthReply struct {
	IsAuthenticated bool
	Error           string
	Account         string
	Name            string
	First           string
	Last            string
	Email           string
	Depart          string
	Avatar          string
}

type QueryReply struct {
	NotExist      bool
	Error         string
	Account       string
	Name          string
	First         string
	Last          string
	Email         string
	Depart        string
	Avatar        string
	City          string
	State         string
	Country       string
	UsageLocation string
}

// Init reading AAD configuration
func Init() {
	var found bool
	if AzureADTenantId, found = revel.Config.String("aad.tenant.id"); !found {
		panic("aad.tenant.id not defined in revel app.conf file")
	} else if AzureADTenantId == "" || strings.TrimSpace(AzureADTenantId) == "" {
		panic("aad.tenant.id cannot be empty before authentication")
	}
	if tempCloudInstance, found := revel.Config.String("aad.cloud.instance"); found &&
		tempCloudInstance != "" && strings.TrimSpace(tempCloudInstance) != "" {
		AzureADCloudInstance = tempCloudInstance
	}
	AzureADTenantAuthority = fmt.Sprintf("%s/%s", utilsgo.TrimSuffix(AzureADCloudInstance, "/"), AzureADTenantId)
	if tempRedirectUrl, found := revel.Config.String("aad.app.redirect.url"); found &&
		tempRedirectUrl != "" && strings.TrimSpace(tempRedirectUrl) != "" {
		AzureADAppRedirectUri = tempRedirectUrl
	}
	if tempLogoutRedirectUrl, found := revel.Config.String("aad.app.logout.redirect.url"); found &&
		tempLogoutRedirectUrl != "" && strings.TrimSpace(tempLogoutRedirectUrl) != "" {
		AzureADAppPostLogoutRedirectUri = tempLogoutRedirectUrl
	}
	if appRedirectHtmlFilePath, found := revel.Config.String("app.redirect.html.file.path"); found &&
		appRedirectHtmlFilePath != "" && strings.TrimSpace(appRedirectHtmlFilePath) != "" {
		AppRedirectHtmlFilePath = appRedirectHtmlFilePath
	}
	if azureOAuth2KeysUrl, found := revel.Config.String("azure.oauth2.keys.url"); found &&
		azureOAuth2KeysUrl != "" && strings.TrimSpace(azureOAuth2KeysUrl) != "" {
		AzureOAuth2KeysUrl = azureOAuth2KeysUrl
	}

	if appAuthLoginApiPath, found := revel.Config.String("app.auth.login.api.path"); found &&
		appAuthLoginApiPath != "" && strings.TrimSpace(appAuthLoginApiPath) != "" {
		AppAuthLoginApiPath = appAuthLoginApiPath
	}
	if accountDomain, found := revel.Config.String("aad.account.primary.domain"); found &&
		accountDomain != "" && strings.TrimSpace(accountDomain) != "" {
		AzureADAccountPrimaryDomain = accountDomain
	}
	if tempAADApiUsersPath, found := revel.Config.String("aad.graph.api.users.path"); found &&
		tempAADApiUsersPath != "" && strings.TrimSpace(tempAADApiUsersPath) != "" {
		AzureADGraphApiUsersPath = tempAADApiUsersPath
	}
	if tempAADApiMePath, found := revel.Config.String("aad.graph.api.me.path"); found &&
		tempAADApiMePath != "" && strings.TrimSpace(tempAADApiMePath) != "" {
		AzureADGraphApiMePath = tempAADApiMePath
	}
	if AzureADAppClientId, found = revel.Config.String("aad.app.client.id"); !found {
		panic("aad.app.client.id not defined in revel app.conf file")
	} else if AzureADAppClientId == "" || strings.TrimSpace(AzureADAppClientId) == "" {
		panic("aad.app.client.id cannot be empty before authentication")
	}
	if AzureADAppClientSecret, found = revel.Config.String("aad.app.client.secret"); !found {
		panic("aad.app.client.secret not defined in revel app.conf file")
	} else if AzureADAppClientSecret == "" || strings.TrimSpace(AzureADAppClientSecret) == "" {
		panic("aad.app.client.secret cannot be empty before authentication")
	}
	if apiPublicScopesStr, found := revel.Config.String("aad.api.public.scopes"); found {
		if apiPublicScopesStr != "" && strings.TrimSpace(apiPublicScopesStr) != "" {
			AzureADApiPublicScopes = utilsgo.RemoveBlankStrings(strings.Split(apiPublicScopesStr, ","))
			if len(AzureADApiPublicScopes) == 0 {
				panic("aad.api.public.scopes cannot be empty items before fetch authentication token")
			}
		}
	}

	if apiCredentialScopesStr, found := revel.Config.String("aad.api.credential.scopes"); found {
		if apiCredentialScopesStr != "" && strings.TrimSpace(apiCredentialScopesStr) != "" {
			AzureADApiCredentialScopes = utilsgo.RemoveBlankStrings(strings.Split(apiCredentialScopesStr, ","))
			if len(AzureADApiCredentialScopes) == 0 {
				panic("aad.api.credential.scopes cannot be empty items before fetch authentication token")
			}
		}
	}
}

// account should be the user's email address.
// https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
// The application should enable public clients https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
// Ask admin to open this configuration in application/Authenticatioin/Advanced Settings/Allow public client flows

func InitPublicClient(account, password string) (*msgraphsdk.GraphServiceClient, error) {
	tempAccount := account
	isMail := utilsgo.MAIL_REGEX.MatchString(tempAccount)
	// construct the username to principal username
	if !isMail && AzureADAccountPrimaryDomain != "" && strings.TrimSpace(AzureADAccountPrimaryDomain) != "" {
		tempAccount = fmt.Sprintf(`%s@%s`, tempAccount, AzureADAccountPrimaryDomain)
	}

	log.Printf("Start initializing Graph service client on %s\n", time.Now())
	cred, err := azidentity.NewUsernamePasswordCredential(
		AzureADTenantId,
		AzureADAppClientId,
		account,
		password,
		nil,
	)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create client with username password credentials: %v", err))
	}

	log.Printf("Start to authenticate for user: %s...", tempAccount)
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, AzureADApiPublicScopes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create graph client with credentials: %v", err))
	}

	return client, nil
}

func InitCredentialClient() (*msgraphsdk.GraphServiceClient, error) {
	cred, err := azidentity.NewClientSecretCredential(
		AzureADTenantId,
		AzureADAppClientId,
		AzureADAppClientSecret,
		nil,
	)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create credentials: %v", err))
	}

	log.Println("Start to creating new Graph Service Client by client credentials")
	log.Println(AzureADTenantId)
	log.Println(AzureADAppClientId)
	log.Println(AzureADAppClientSecret)
	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, AzureADApiCredentialScopes)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to create client with client credentials: %v", err))
	}

	return client, nil
}

// Authenticate do auth and return Auth object including user information and lognin success or not
// Required Delegated Permission: User.Read, and Grant admin consent as this is a Daemon web api.
// account could be the pricipal user name in AAD or mail of login user
func AuthenticatePublicClient(account, password string) *AuthReply {
	authReply := &AuthReply{}
	// below Call will return error when using credentials client
	msGraphClient, err := InitPublicClient(account, password)
	if err != nil {
		log.Println("Init client failed: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	requestParameters := &msgraphsdkme.MeRequestBuilderGetQueryParameters{
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId", "onPremisesSamAccountName"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId", "onPremisesSamAccountName"},
	}
	configuration := &msgraphsdkme.MeRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}
	// retrieve the sign in user information from AAD
	currentUserReponse, err := msGraphClient.Me().Get(context.Background(), configuration)
	if err != nil || currentUserReponse.GetId() == nil {
		log.Println("Retrieving user failed with error: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	authReply.IsAuthenticated = true
	if currentUserReponse.GetOnPremisesSamAccountName() != nil {
		authReply.Account = *currentUserReponse.GetOnPremisesSamAccountName()
	} else if currentUserReponse.GetEmployeeId() != nil {
		authReply.Account = *currentUserReponse.GetEmployeeId()
	}
	if currentUserReponse.GetDisplayName() != nil {
		authReply.Name = *currentUserReponse.GetDisplayName()
	}
	if currentUserReponse.GetGivenName() != nil {
		authReply.First = *currentUserReponse.GetGivenName()
	}
	if currentUserReponse.GetSurname() != nil {
		authReply.Last = *currentUserReponse.GetSurname()
	}
	if currentUserReponse.GetMail() != nil {
		authReply.Email = *currentUserReponse.GetMail()
	}
	if currentUserReponse.GetDepartment() != nil {
		authReply.Depart = *currentUserReponse.GetDepartment()
	}
	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		authReply.Avatar = QueryUserPhotoById(*currentUserReponse.GetId(), token)
	}
	return authReply
}

func AuthenticateByClientCredentials(account string) *AuthReply {
	authReply := &AuthReply{}
	tempAccount := account
	isMail := utilsgo.MAIL_REGEX.MatchString(tempAccount)
	// construct the username to principal username
	if !isMail && AzureADAccountPrimaryDomain != "" && strings.TrimSpace(AzureADAccountPrimaryDomain) != "" {
		tempAccount = fmt.Sprintf(`%s@%s`, tempAccount, AzureADAccountPrimaryDomain)
	}

	msGraphClient, err := InitCredentialClient()
	if err != nil {
		log.Println("Retrieving user failed with error: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	requestParameters := &msgraphsdkusers.UserItemRequestBuilderGetQueryParameters{
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId", "onPremisesSamAccountName"
		Select: []string{"id", "displayName", "givenName", "surname", "mail", "department", "employeeId", "onPremisesSamAccountName"},
	}
	configuration := &msgraphsdkusers.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}
	// below Call will return error when using credentials client
	currentUserReponse, err := msGraphClient.UsersById(tempAccount).Get(context.Background(), configuration)
	if err != nil || currentUserReponse.GetId() == nil {
		log.Println("Retrieving user failed: ", err)
		authReply.Error = fmt.Sprintf("%v", err)
		return authReply
	}

	authReply.IsAuthenticated = true
	if currentUserReponse.GetOnPremisesSamAccountName() != nil {
		authReply.Account = *currentUserReponse.GetOnPremisesSamAccountName()
	} else if currentUserReponse.GetEmployeeId() != nil {
		authReply.Account = *currentUserReponse.GetEmployeeId()
	}
	if currentUserReponse.GetDisplayName() != nil {
		authReply.Name = *currentUserReponse.GetDisplayName()
	}
	if currentUserReponse.GetGivenName() != nil {
		authReply.First = *currentUserReponse.GetGivenName()
	}
	if currentUserReponse.GetSurname() != nil {
		authReply.Last = *currentUserReponse.GetSurname()
	}
	if currentUserReponse.GetMail() != nil {
		authReply.Email = *currentUserReponse.GetMail()
	}
	if currentUserReponse.GetDepartment() != nil {
		authReply.Depart = *currentUserReponse.GetDepartment()
	}
	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		authReply.Avatar = QueryUserPhotoById(*currentUserReponse.GetId(), token)
	}
	return authReply
}

func AcquirePublicToken(account, password string) (string, error) {
	_, filename, _, _ := runtime.Caller(0)
	curDir := path.Dir(filename)
	var cacheAccessor = &cache.TokenCache{File: curDir + "/cache/serialized_cache.json"}

	log.Println("Start to fetch access token from AAD by account and password...")
	app, err := azauthlibgopublic.New(AzureADAppClientId, azauthlibgopublic.WithCache(cacheAccessor), azauthlibgopublic.WithAuthority(AzureADTenantAuthority))
	if err != nil {
		return "", err
	}

	// look in the cache to see if the account to use has been cached
	var userAccount azauthlibgopublic.Account
	accounts := app.Accounts()
	for _, accountItem := range accounts {
		if accountItem.PreferredUsername == account {
			userAccount = accountItem
		}
	}
	// found a cached account, now see if an applicable token has been cached
	// NOTE: this API conflates error states, i.e. err is non-nil if an applicable token isn't
	//       cached or if something goes wrong (making the HTTP request, unmarshalling, etc).
	result, err := app.AcquireTokenSilent(
		context.Background(),
		AzureADApiPublicScopes,
		azauthlibgopublic.WithSilentAccount(userAccount),
	)
	if err != nil {
		// either there's no applicable token in the cache or something failed
		log.Println(err)
		// either there was no cached account/token or the call to AcquireTokenSilent() failed
		// make a new request to AAD
		result, err = app.AcquireTokenByUsernamePassword(
			context.Background(),
			AzureADApiPublicScopes,
			account,
			password,
		)
		if err != nil {
			return "", err
		}
		fmt.Println("New acquired token " + result.AccessToken)
		return result.AccessToken, nil
	}
	fmt.Println("New acquired token " + result.AccessToken)
	return result.AccessToken, nil
}

func AcquireCredentialToken() (string, error) {
	_, filename, _, _ := runtime.Caller(0)
	curDir := path.Dir(filename)
	var cacheAccessor = &cache.TokenCache{File: curDir + "/cache/serialized_cache.json"}

	cred, err := azauthlibgocred.NewCredFromSecret(AzureADAppClientSecret)
	if err != nil {
		return "", err
	}

	log.Println("Start to fetch access token from AAD...")
	client, err := azauthlibgocred.New(AzureADAppClientId, cred, azauthlibgocred.WithAuthority(AzureADTenantAuthority), azauthlibgocred.WithAccessor(cacheAccessor))
	if err != nil {
		return "", err
	}
	result, err := client.AcquireTokenSilent(context.Background(), AzureADApiCredentialScopes)
	if err != nil {
		result, err = client.AcquireTokenByCredential(context.Background(), AzureADApiCredentialScopes)
		if err != nil {
			return "", err
		}
		// fmt.Println("New acquired token with client credentials: " + result.AccessToken)
		return result.AccessToken, nil
	}
	// fmt.Println("New acquired silent token with client credentials: " + result.AccessToken)
	return result.AccessToken, nil
}

// https://learn.microsoft.com/en-us/graph/query-parameters?context=graph%2Fapi%2F1.0&view=graph-rest-1.0
func Query(userIdentity string) *QueryReply {
	if userIdentity == "" || strings.TrimSpace(userIdentity) == "" {
		return &QueryReply{Error: fmt.Sprintf("Invalid user identity input, please provide a valid user identity.")}
	}
	queryReply := &QueryReply{}
	msGraphClient, err := InitCredentialClient()
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Init Graph Service client failed with error: %v", err)}
	}

	// https://learn.microsoft.com/en-us/graph/aad-advanced-queries?tabs=http should add ConsistencyLevel: eventual and $count=true
	requestCount := true
	// requestFilter := fmt.Sprintf("employeeId eq '%s'", userIdentity)
	requestFilter := fmt.Sprintf("onPremisesSamAccountName eq '%s' or employeeId eq '%s'", userIdentity, userIdentity)
	requestParameters := &msgraphsdkusers.UsersRequestBuilderGetQueryParameters{
		Count:  &requestCount,
		Filter: &requestFilter,
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId", "onPremisesSamAccountName"
		Select: querySelect,
	}
	requestHeaders := kiotaabstractions.NewRequestHeaders()
	requestHeaders.Add("ConsistencyLevel", "eventual")
	configuration := &msgraphsdkusers.UsersRequestBuilderGetRequestConfiguration{
		Headers:         requestHeaders,
		QueryParameters: requestParameters,
	}

	log.Printf("Querying user info for: %s by Identity", userIdentity)
	usersResponse, err := msGraphClient.Users().Get(context.Background(), configuration)
	if err != nil {
		log.Println(fmt.Sprintf("Querying user %s info failed with error: %v", userIdentity, err))
		return &QueryReply{Error: fmt.Sprintf("Querying user %s info failed with error: %v", userIdentity, getOdataError(err))}
	}

	usersResponseValue := usersResponse.GetValue()
	if len(usersResponseValue) == 0 {
		log.Printf("User: %s not found", userIdentity)
		queryReply.NotExist = true
		queryReply.Error = fmt.Sprintf("account %s not exist", userIdentity)
		return queryReply
	}

	if usersResponseValue[0].GetOnPremisesSamAccountName() != nil {
		queryReply.Account = *usersResponseValue[0].GetOnPremisesSamAccountName()
	} else if usersResponseValue[0].GetEmployeeId() != nil {
		queryReply.Account = *usersResponseValue[0].GetEmployeeId()
	}

	if queryReply.Account == "" || usersResponseValue[0].GetId() == nil {
		queryReply.Error = fmt.Sprintf("account %s not exist", userIdentity)
		queryReply.NotExist = true
		return queryReply
	}

	genQueryReply(usersResponseValue, queryReply)

	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		queryReply.Avatar = QueryUserPhotoById(*usersResponseValue[0].GetId(), token)
	}

	return queryReply
}

// https://learn.microsoft.com/en-us/graph/query-parameters?context=graph%2Fapi%2F1.0&view=graph-rest-1.0
func QueryMail(emailAddress string) *QueryReply {
	isMail := utilsgo.MAIL_REGEX.MatchString(emailAddress)
	// construct the username to principal username
	if !isMail {
		return &QueryReply{Error: fmt.Sprintf("Invalid email address, please provide a valid email address.")}
	}
	queryReply := &QueryReply{}
	msGraphClient, err := InitCredentialClient()
	if err != nil {
		return &QueryReply{Error: fmt.Sprintf("Init Graph Service client failed with error: %v", err)}
	}

	requestCount := true
	requestFilter := fmt.Sprintf("mail eq '%s'", emailAddress)
	requestParameters := &msgraphsdkusers.UsersRequestBuilderGetQueryParameters{
		Count:  &requestCount,
		Filter: &requestFilter,
		// "id", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "postalCode", "identities", "mail", "department", "employeeId", "onPremisesSamAccountName"
		Select: querySelect,
	}
	configuration := &msgraphsdkusers.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: requestParameters,
	}

	log.Printf("Querying user info for: %s by Email", emailAddress)
	usersResponse, err := msGraphClient.Users().Get(context.Background(), configuration)
	if err != nil {
		log.Println(fmt.Sprintf("Querying user %s info failed with error: %v", emailAddress, err))
		return &QueryReply{Error: fmt.Sprintf("querying user %s info failed with error: %v", emailAddress, getOdataError(err))}
	}

	usersResponseValue := usersResponse.GetValue()
	if len(usersResponseValue) == 0 {
		log.Printf("User: %s not found", emailAddress)
		queryReply.NotExist = true
		queryReply.Error = fmt.Sprintf("account %s not exist", emailAddress)
		return queryReply
	}

	if usersResponseValue[0].GetOnPremisesSamAccountName() != nil {
		queryReply.Account = *usersResponseValue[0].GetOnPremisesSamAccountName()
	} else if usersResponseValue[0].GetEmployeeId() != nil {
		queryReply.Account = *usersResponseValue[0].GetEmployeeId()
	}

	if queryReply.Account == "" || usersResponseValue[0].GetId() == nil {
		queryReply.Error = fmt.Sprintf("account %s not exist", emailAddress)
		queryReply.NotExist = true
		return queryReply
	}

	genQueryReply(usersResponseValue, queryReply)

	// Better to read photo via SDK
	// userPhoto := userResponseValue[0].GetPhoto()
	token, err := AcquireCredentialToken()
	if err != nil {
		log.Printf("Acquire token to fetch user photo failed with error: %v", err)
	} else {
		queryReply.Avatar = QueryUserPhotoById(*usersResponseValue[0].GetId(), token)
	}

	return queryReply
}

func genQueryReply(usersResponseValue []msgraphsdkmodel.Userable, queryReply *QueryReply) {
	if usersResponseValue[0].GetDisplayName() != nil {
		queryReply.Name = *usersResponseValue[0].GetDisplayName()
	}
	if usersResponseValue[0].GetGivenName() != nil {
		queryReply.First = *usersResponseValue[0].GetGivenName()
	}
	if usersResponseValue[0].GetSurname() != nil {
		queryReply.Last = *usersResponseValue[0].GetSurname()
	}
	if usersResponseValue[0].GetMail() != nil {
		queryReply.Email = *usersResponseValue[0].GetMail()
	}
	if usersResponseValue[0].GetDepartment() != nil {
		queryReply.Depart = *usersResponseValue[0].GetDepartment()
	}
	if usersResponseValue[0].GetState() != nil {
		queryReply.State = *usersResponseValue[0].GetState()
	}
	if usersResponseValue[0].GetCity() != nil {
		queryReply.City = *usersResponseValue[0].GetCity()
	}
	if usersResponseValue[0].GetCountry() != nil {
		queryReply.Country = *usersResponseValue[0].GetCountry()
	}
	if usersResponseValue[0].GetUsageLocation() != nil {
		queryReply.UsageLocation = *usersResponseValue[0].GetUsageLocation()
	}
}

func QueryMailAndSave(email string) (*models.User, error) {
	authUser := QueryMail(email)

	if authUser.Error != "" && authUser.Error != "<nil>" {
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		return nil, fmt.Errorf("User not exist")
	}

	user := genQueryUser(authUser.Account, authUser)
	s := revmongo.NewMgoSession()
	defer s.Close()
	user.SaveUser(s)
	return user, nil
}

func QueryAndSave(account string) (*models.User, error) {
	authUser := Query(account)

	if authUser.Error != "" && authUser.Error != "<nil>" {
		return nil, fmt.Errorf(authUser.Error)
	}
	if authUser.NotExist {
		return nil, fmt.Errorf("User not exist")
	}

	user := genQueryUser(account, authUser)
	s := revmongo.NewMgoSession()
	defer s.Close()
	user.SaveUser(s)
	return user, nil
}

func genQueryUser(account string, authUser *QueryReply) *models.User {
	user := new(models.User)
	user.Identity = strings.ToLower(account)
	user.Mail = authUser.Email
	user.Avatar = authUser.Avatar
	user.Name = authUser.Name
	user.Depart = authUser.Depart
	user.UsageLocation = authUser.UsageLocation
	additionalSettings := make(map[string]interface{})
	if authUser.Country != "" {
		additionalSettings["Country"] = authUser.Country
	}
	if authUser.State != "" {
		additionalSettings["State"] = authUser.State
	}
	if authUser.City != "" {
		additionalSettings["City"] = authUser.City
	}
	if len(additionalSettings) > 0 {
		user.AdditionalSettings = additionalSettings
	}
	return user
}

func QueryUserPhotoById(userId, token string) string {
	if userId == "" || token == "" {
		return ""
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	queryUrl := utilsgo.TrimSuffix(AzureADGraphApiUsersPath, "/") + fmt.Sprintf("/%s/photo/$value", userId)
	data, err := httpclient.GetJson(queryUrl, "", headers)
	if err != nil {
		log.Printf("Query user photo failed with error: %v", err)
		return ""
	}

	log.Println("Fetch user photo successfully")
	return base64.StdEncoding.EncodeToString(data)
}

func QueryUserPhotoByName(username, token string) string {
	if username == "" || token == "" {
		return ""
	}

	principalName := username
	isMail := utilsgo.MAIL_REGEX.MatchString(username)
	if !isMail && AzureADAccountPrimaryDomain != "" && strings.TrimSpace(AzureADAccountPrimaryDomain) != "" {
		principalName = fmt.Sprintf(`%s@%s`, principalName, AzureADAccountPrimaryDomain)
	}

	headers := map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", token),
	}
	queryUrl := utilsgo.TrimSuffix(AzureADGraphApiUsersPath, "/") + fmt.Sprintf("/%s/photo/$value", username)
	data, err := httpclient.GetJson(queryUrl, "", headers)
	if err != nil {
		log.Printf("Query user photo failed with error: %v", err)
		return ""
	}

	log.Println("Fetch user photo successfully")
	return base64.StdEncoding.EncodeToString(data)
}

func getOdataError(err error) string {
	switch err.(type) {
	case *odataerrors.ODataError:
		typed := err.(*odataerrors.ODataError)
		if terr := typed.GetError(); terr != nil {
			return fmt.Sprintf("code: %s, msg: %s", *terr.GetCode(), *terr.GetMessage())
		}
	default:
		return fmt.Sprintf("%T > error: %#v", err, err)
	}
	return fmt.Sprintf("%T > error: %#v", err, err)
}
