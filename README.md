# Authentication with Azure Active Directory(AAD)

# Usage:

## Installation

Install module

```
# specific version
go get go get github.com/QFO6/rev-auth-aad@vx.x.x
# or get latest
go get github.com/QFO6/rev-auth-aad@<branch_name>
```

Include revel config variables in Revel Application file conf/app.conf

```
# Mongo Database related configurations
mongodb.dial=${mongodb_dial}
mongodb.name=${mongodb_name}

# Azure AD related configurations
# Module
module.revauthaad = github.com/QFO6/rev-auth-aad

aad.tenant.id=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.app.client.id=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.app.client.secret=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx
aad.account.primary.domain=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aad.cloud.instance=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx          # default: https://login.microsoftonline.com
aad.graph.api.me.path=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx       # default: https://graph.microsoft.com/v1.0/me
aad.graph.api.users.path=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx    # default: https://graph.microsoft.com/v1.0/users
aad.api.public.scopes=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx       # default: User.Read
aad.api.credential.scopes=xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxx   # default: https://graph.microsoft.com/.default
aad.app.redirect.url=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx      # default: '/'
aad.app.logout.redirect.url=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx     # default: http://localhost:3000/login
app.redirect.html.file.path=xxxxxxxxxxxxxxxxxxxxxxxxxxx        # default: /public/lib/msal/redirect.html
app.auth.login.api.path=xxxxxxxxxxxxxxxxxxxxxxxxxxx            # default: /login/v2
```

Overwrite OAuth2.0 key url

```
azure.oauth2.keys.url=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx         # default: https://login.microsoftonline.com/common/discovery/v2.0/keys
```

Include module in Revel Application file: conf/routes

```
module:revauthaad
```

Needs to define routes in under your revel_app/conf/routes file

```
GET                   /api/v1/auth/logout                                            Auth.Logout
POST                  /api/v1/auth/logout                                            Auth.Logout
POST                  /api/v1/auth/login                                             Auth.Authenticate
GET                   /api/v1/auth/login-check                                       Auth.CheckLogin

GET                   /api/v2/auth/logout                                            AppAuth.Logout
POST                  /api/v2/auth/login/:identity                                   AppAuth.Authenticate
GET                   /api/v2/auth/login-check                                       AppAuth.CheckLogin
```

Init module in Revel Application file app/init.go

```
// Import
revmongo "github.com/QFO6/rev-mongo"
revauthaad "github.com/QFO6/rev-auth-aad"

revel.OnAppStart(revmongo.Init, 0)
revel.OnAppStart(revauthaad.Init, 1) // make sure revmongo before revauthaad, otherwise will raise nil panic
```

The Azure AD Cloud Instance options include;

```
https://login.microsoftonline.com/ for Azure public cloud
https://login.microsoftonline.us/ for Azure US government
https://login.microsoftonline.de/ for Azure AD Germany
https://login.partner.microsoftonline.cn/common for Azure AD China operated by 21Vianet
```

## Setup E2E Test

Include revel config variables in Revel Application file conf/app.conf

```
e2e.test.login.account=xxxxxxxxxxxx
```
