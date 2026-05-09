package wso2

import "net/http"

type Client struct {
	BaseURL    string
	Username   string
	Password   string
	Tenant     string
	httpClient *http.Client
}

type Response struct {
	Body       []byte
	StatusCode int
	Location   string
}

type ContentType string

const (
	ContentTypeJSON ContentType = "application/json"
	ContentTypeSOAP ContentType = "text/xml; charset=utf-8"
)

type RequestOptions struct {
	ContentType ContentType
	Accept      string
	SOAPAction  string
}

type Claim struct {
	URI       string `json:"uri"`
	Mandatory bool   `json:"mandatory"`
}

type OAuth2Config struct {
	CallbackURL string   `json:"callbackURL"`
	GrantTypes  []string `json:"grantTypes"`

	PKCEMandatory bool `json:"pkceMandatory,omitempty"`
	PKCEPlain     bool `json:"pkcePlain,omitempty"`
	PublicClient  bool `json:"publicClient,omitempty"`

	TokenBinding    string   `json:"tokenBinding,omitempty"`
	Audiences       []string `json:"audiences,omitempty"`
	ScopeValidators []string `json:"scopeValidators,omitempty"`

	RefreshTokenExpiry  int    `json:"refreshTokenExpiry,omitempty"`
	AccessTokenExpiry   int    `json:"accessTokenExpiry,omitempty"`
	OAuthConsumerKey    string `json:"oauthConsumerKey,omitempty"`
	OAuthConsumerSecret string `json:"oauthConsumerSecret,omitempty"`
}

type AuthenticationStep struct {
	Step                   int      `json:"step"`
	LocalAuthenticators    []string `json:"localAuthenticators,omitempty"`
	FederatedIDP           string   `json:"federatedIDP,omitempty"`
	FederatedAuthenticator string   `json:"FederatedAuthenticator,omitempty"`
}

type Application struct {
	ID          int    `json:"id"`
	ResourceID  string `json:"resourceID"`
	Name        string `json:"name"`
	Description string `json:"description"`

	Claims          []Claim `json:"claims,omitempty"`
	SubjectClaimURI string  `json:"subjectURI,omitempty"`

	OAuth2               *OAuth2Config        `json:"oauth2"`
	AuthenticationSteps  []AuthenticationStep `json:"authenticationStep"`
	AuthenticationScript string               `json:"authenticationScript"`

	AlwaysSendBackAuthenticatedListOfIDPs bool `json:"alwaysSendBackAuthenticatedListOfIDPs,omitempty"`
	EnableAuthorization                   bool `json:"enableAuthorization"`
	SkipConsent                           bool `json:"skipConsent"`
	SkipLogoutConsent                     bool `json:"skipLogoutConsent"`
	UseTenantInSub                        bool `json:"useTenantInSub"`
	UseUserstoreInSub                     bool `json:"useUserstoreInSub"`
	UseUserstoreInRoles                   bool `json:"useUserstoreInRoles"`

	StepForSubject    int `json:"stepForSubject,omitempty"`
	StepForAttributes int `json:"stepForAttr,omitempty"`
}
