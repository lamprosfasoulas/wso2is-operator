package wso2

import (
	"encoding/xml"
)

const (
	SoapEnvNS = "http://schemas.xmlsoap.org/soap/envelope/"
	AxisNS    = "http://org.apache.axis2/xsd"
	CommonNS  = "http://model.common.application.identity.carbon.wso2.org/xsd"
	OAuthNS   = "http://dto.oauth.identity.carbon.wso2.org/xsd"
)

// ── ENVELOPES ────────────────────────────────────────────────────────────────

// RequestEnvelope is used for marshaling outgoing SOAP requests.
// Literal prefix tags are intentional — Go outputs them as-is.
type RequestEnvelope[T any] struct {
	XMLName xml.Name `xml:"soapenv:Envelope"`
	SoapEnv string   `xml:"xmlns:soapenv,attr"`
	XSD     string   `xml:"xmlns:xsd,attr"`
	XSD1    string   `xml:"xmlns:xsd1,attr,omitempty"`
	Body    T        `xml:"soapenv:Body"`
}

// ResponseEnvelope is used for unmarshaling incoming SOAP responses.
// Namespace URI tags are required — Go resolves prefixes to URIs during parse.
type ResponseEnvelope[T any] struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Body    T        `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
}

// ── SERVICE PROVIDER — SOAP BODIES ───────────────────────────────────────────

type CreateApplicationBody struct {
	CreateApplication CreateApplicationRequest `xml:"xsd:createApplication"`
}

type CreateApplicationRequest struct {
	ServiceProvider ServiceProviderRequest `xml:"xsd:serviceProvider"`
}

type GetApplicationBody struct {
	GetApplication GetApplicationRequest `xml:"xsd:getApplication"`
}

type GetApplicationRequest struct {
	ApplicationName string `xml:"xsd:applicationName"`
}

type UpdateApplicationBody struct {
	UpdateApplication UpdateApplicationRequest `xml:"xsd:updateApplication"`
}

type UpdateApplicationRequest struct {
	ServiceProvider ServiceProviderRequest `xml:"xsd:serviceProvider"`
}

type DeleteApplicationBody struct {
	DeleteApplication DeleteApplicationRequest `xml:"xsd:deleteApplication"`
}

type DeleteApplicationRequest struct {
	ApplicationName string `xml:"xsd:applicationName"`
}

type GetApplicationResponseBody struct {
	GetApplicationResponse GetApplicationResponse `xml:"http://org.apache.axis2/xsd getApplicationResponse"`
}

type GetApplicationResponse struct {
	ServiceProvider ServiceProviderResponse `xml:"http://org.apache.axis2/xsd return"`
}

// ── SERVICE PROVIDER — REQUEST (marshal) ─────────────────────────────────────

type ServiceProviderRequest struct {
	ApplicationID         int    `xml:"xsd1:applicationID,omitempty"`
	ApplicationResourceID string `xml:"xsd1:applicationResourceID,omitempty"`
	ApplicationName       string `xml:"xsd1:applicationName"`
	Description           string `xml:"xsd1:description,omitempty"`

	ClaimConfig                          *ClaimConfigRequest                          `xml:"xsd1:claimConfig,omitempty"`
	InboundAuthenticationConfig          *InboundAuthenticationConfigRequest          `xml:"xsd1:inboundAuthenticationConfig,omitempty"`
	LocalAndOutboundAuthenticationConfig *LocalAndOutboundAuthenticationConfigRequest `xml:"xsd1:localAndOutBoundAuthenticationConfig,omitempty"`
}

type ClaimConfigRequest struct {
	AlwaysSendMappedLocalSubjectID string                `xml:"xsd1:alwaysSendMappedLocalSubjectId"`
	LocalClaimDialect              bool                  `xml:"xsd1:localClaimDialect"`
	ClaimMappings                  []ClaimMappingRequest `xml:"xsd1:claimMappings,omitempty"`
	UserClaimURI                   string                `xml:"xsd1:userClaimURI,omitempty"`
}

type ClaimMappingRequest struct {
	LocalClaim  ClaimRequest `xml:"xsd1:localClaim"`
	RemoteClaim ClaimRequest `xml:"xsd1:remoteClaim"`
	Mandatory   bool         `xml:"xsd1:mandatory"`
	Requested   bool         `xml:"xsd1:requested"`
}

type ClaimRequest struct {
	ClaimURI string `xml:"xsd1:claimUri"`
}

type InboundAuthenticationConfigRequest struct {
	InboundAuthenticationRequestConfigs []InboundAuthenticationRequestConfigRequest `xml:"xsd1:inboundAuthenticationRequestConfigs"`
}

type InboundAuthenticationRequestConfigRequest struct {
	InboundAuthKey  string            `xml:"xsd1:inboundAuthKey"`
	InboundAuthType string            `xml:"xsd1:inboundAuthType"`
	Properties      []PropertyRequest `xml:"xsd1:properties,omitempty"`
}

type PropertyRequest struct {
	Name  string `xml:"xsd1:name"`
	Value string `xml:"xsd1:value"`
}

type LocalAndOutboundAuthenticationConfigRequest struct {
	AlwaysSendBackAuthenticatedListOfIDPs bool                              `xml:"xsd1:alwaysSendBackAuthenticatedListOfIdPs"`
	AuthenticationScriptConfig            AuthenticationScriptConfigRequest `xml:"xsd1:authenticationScriptConfig,omitempty"`
	AuthenticationSteps                   []AuthenticationStepRequest       `xml:"xsd1:authenticationSteps"`
	AuthenticationType                    string                            `xml:"xsd1:authenticationType,omitempty"`
	SubjectClaimURI                       string                            `xml:"xsd1:subjectClaimUri,omitempty"`
	AuthenticationScript                  string                            `xml:"xsd1:authenticationScript,omitempty"`

	EnableAuthorization                        bool `xml:"xsd1:enableAuthorization"`
	SkipConsent                                bool `xml:"xsd1:skipConsent"`
	SkipLogoutConsent                          bool `xml:"xsd1:skipLogoutConsent"`
	UseTenantDomainInLocalSubjectIdentifier    bool `xml:"xsd1:useTenantDomainInLocalSubjectIdentifier"`
	UseUserstoreDomainInLocalSubjectIdentifier bool `xml:"xsd1:useUserstoreDomainInLocalSubjectIdentifier"`
	UseUserstoreDomainInRoles                  bool `xml:"xsd1:useUserstoreDomainInRoles"`
}

type AuthenticationStepRequest struct {
	FederatedIdentityProviders *[]FederatedIdentityProvidersRequest `xml:"xsd1:federatedIdentityProviders,omitempty"`
	LocalAuthenticatorConfigs  []LocalAuthenticatorConfigRequest    `xml:"xsd1:localAuthenticatorConfigs,omitempty"`
	StepOrder                  int                                  `xml:"xsd1:stepOrder"`
	SubjectStep                bool                                 `xml:"xsd1:subjectStep"`
	AttributeStep              bool                                 `xml:"xsd1:attributeStep"`
}

type FederatedIdentityProvidersRequest struct {
	FederatedAuthenticatiorConfig []FederatedAuthenticatiorConfigRequest `xml:"xsd1:federatedAuthenticatorConfigs,omitempty"`
	IdentityProviderName          string                                 `xml:"xsd1:identityProviderName,omitempty"`
}

type FederatedAuthenticatiorConfigRequest struct {
	DisplayName string `xml:"xsd1:displayName"`
	Name        string `xml:"xsd1:name"`
	Valid       bool   `xml:"xsd1:valid,omitempty"`
}

type LocalAuthenticatorConfigRequest struct {
	DisplayName string `xml:"xsd1:displayName"`
	Name        string `xml:"xsd1:name"`
	Valid       bool   `xml:"xsd1:valid"`
}

type AuthenticationScriptConfigRequest struct {
	Content  string `xml:"xsd1:content"`
	Enabled  bool   `xml:"xsd1:enabled"`
	Language string `xml:"xsd1:language"`
}

// ── SERVICE PROVIDER — RESPONSE (unmarshal) ───────────────────────────────────

type ServiceProviderResponse struct {
	ApplicationID         int    `xml:"http://model.common.application.identity.carbon.wso2.org/xsd applicationID"`
	ApplicationResourceID string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd applicationResourceId"`
	ApplicationName       string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd applicationName"`
	Description           string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd description,omitempty"`

	ClaimConfig                          *ClaimConfigResponse                          `xml:"http://model.common.application.identity.carbon.wso2.org/xsd claimConfig,omitempty"`
	InboundAuthenticationConfig          *InboundAuthenticationConfigResponse          `xml:"http://model.common.application.identity.carbon.wso2.org/xsd inboundAuthenticationConfig,omitempty"`
	LocalAndOutboundAuthenticationConfig *LocalAndOutboundAuthenticationConfigResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd localAndOutBoundAuthenticationConfig,omitempty"`
}

type ClaimConfigResponse struct {
	AlwaysSendMappedLocalSubjectID string                 `xml:"http://model.common.application.identity.carbon.wso2.org/xsd alwaysSendMappedLocalSubjectId"`
	LocalClaimDialect              string                 `xml:"http://model.common.application.identity.carbon.wso2.org/xsd localClaimDialect"`
	ClaimMappings                  []ClaimMappingResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd claimMappings,omitempty"`
	UserClaimURI                   string                 `xml:"http://model.common.application.identity.carbon.wso2.org/xsd userClaimURI,omitempty"`
}

type ClaimMappingResponse struct {
	LocalClaim  ClaimResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd localClaim"`
	RemoteClaim ClaimResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd remoteClaim"`
	Mandatory   bool          `xml:"http://model.common.application.identity.carbon.wso2.org/xsd mandatory"`
	Requested   bool          `xml:"http://model.common.application.identity.carbon.wso2.org/xsd requested"`
}

type ClaimResponse struct {
	ClaimURI string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd claimUri"`
}

type InboundAuthenticationConfigResponse struct {
	InboundAuthenticationRequestConfigs []InboundAuthenticationRequestConfigResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd inboundAuthenticationRequestConfigs"`
}

type InboundAuthenticationRequestConfigResponse struct {
	InboundAuthKey  string             `xml:"http://model.common.application.identity.carbon.wso2.org/xsd inboundAuthKey"`
	InboundAuthType string             `xml:"http://model.common.application.identity.carbon.wso2.org/xsd inboundAuthType"`
	Properties      []PropertyResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd properties,omitempty"`
}

type PropertyResponse struct {
	Name  string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd name"`
	Value string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd value"`
}

type LocalAndOutboundAuthenticationConfigResponse struct {
	AlwaysSendBackAuthenticatedListOfIDPs bool                               `xml:"http://model.common.application.identity.carbon.wso2.org/xsd alwaysSendBackAuthenticatedListOfIdPs"`
	AuthenticationSteps                   []AuthenticationStepResponse       `xml:"http://model.common.application.identity.carbon.wso2.org/xsd authenticationSteps"`
	AuthenticationScriptConfig            AuthenticationScriptConfigResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd authenticationScriptConfig"`
	AuthenticationType                    string                             `xml:"http://model.common.application.identity.carbon.wso2.org/xsd authenticationType,omitempty"`
	SubjectClaimURI                       string                             `xml:"http://model.common.application.identity.carbon.wso2.org/xsd subjectClaimUri,omitempty"`
	AuthenticationScript                  string                             `xml:"http://model.common.application.identity.carbon.wso2.org/xsd authenticationScript,omitempty"`

	EnableAuthorization                        bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd enableAuthorization"`
	SkipConsent                                bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd skipConsent"`
	SkipLogoutConsent                          bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd skipLogoutConsent"`
	UseTenantDomainInLocalSubjectIdentifier    bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd useTenantDomainInLocalSubjectIdentifier"`
	UseUserstoreDomainInLocalSubjectIdentifier bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd useUserstoreDomainInLocalSubjectIdentifier"`
	UseUserstoreDomainInRoles                  bool `xml:"http://model.common.application.identity.carbon.wso2.org/xsd useUserstoreDomainInRoles"`
}

type AuthenticationStepResponse struct {
	FederatedIdentityProviders []FederatedIdentityProvidersResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd federatedIdentityProviders"`
	LocalAuthenticatorConfigs  []LocalAuthenticatorConfigResponse   `xml:"http://model.common.application.identity.carbon.wso2.org/xsd localAuthenticatorConfigs"`
	StepOrder                  int                                  `xml:"http://model.common.application.identity.carbon.wso2.org/xsd stepOrder"`
	SubjectStep                bool                                 `xml:"http://model.common.application.identity.carbon.wso2.org/xsd subjectStep"`
	AttributeStep              bool                                 `xml:"http://model.common.application.identity.carbon.wso2.org/xsd attributeStep"`
}

type FederatedIdentityProvidersResponse struct {
	FederatedAuthenticatiorConfig []FederatedAuthenticatiorConfigResponse `xml:"http://model.common.application.identity.carbon.wso2.org/xsd federatedAuthenticatorConfigs"`
	IdentityProviderName          string                                  `xml:"http://model.common.application.identity.carbon.wso2.org/xsd identityProviderName"`
}

type FederatedAuthenticatiorConfigResponse struct {
	DisplayName string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd displayName"`
	Name        string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd name"`
	Valid       bool   `xml:"http://model.common.application.identity.carbon.wso2.org/xsd valid"`
}

type LocalAuthenticatorConfigResponse struct {
	DisplayName string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd displayName"`
	Name        string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd name"`
	Valid       bool   `xml:"http://model.common.application.identity.carbon.wso2.org/xsd valid"`
}

type AuthenticationScriptConfigResponse struct {
	Content  string `xml:"http://script.model.common.application.identity.carbon.wso2.org/xsd content"`
	Enabled  bool   `xml:"http://script.model.common.application.identity.carbon.wso2.org/xsd enabled"`
	Language string `xml:"http://script.model.common.application.identity.carbon.wso2.org/xsd language"`
	// Content  string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd content"`
	// Enabled  bool   `xml:"http://model.common.application.identity.carbon.wso2.org/xsd enabled"`
	// Language string `xml:"http://model.common.application.identity.carbon.wso2.org/xsd language"`
}

// ── OAUTH — SOAP BODIES ───────────────────────────────────────────────────────

type RegisterOAuthBody struct {
	RegisterOAuthApplicationData RegisterOAuthApplicationDataRequest `xml:"xsd:registerOAuthApplicationData"`
}

type RegisterOAuthApplicationDataRequest struct {
	Application OAuthApplication `xml:"xsd:application"`
}

type GetOAuthBody struct {
	GetOAuthApplicationDataByAppName GetOAuthApplicationDataByAppNameRequest `xml:"xsd:getOAuthApplicationDataByAppName"`
}

type GetOAuthApplicationDataByAppNameRequest struct {
	AppName string `xml:"xsd:appName"`
}

type UpdateOAuthBody struct {
	UpdateConsumerApplication UpdateConsumerApplicationRequest `xml:"xsd:updateConsumerApplication"`
}

type UpdateConsumerApplicationRequest struct {
	ConsumerAppDTO OAuthApplication `xml:"xsd:consumerAppDTO"`
}

type GetOAuthApplicationDataByAppNameResponseBody struct {
	GetOAuthApplicationDataByAppNameResponse GetOAuthApplicationDataByAppNameResponse `xml:"http://org.apache.axis2/xsd getOAuthApplicationDataByAppNameResponse"`
}

type GetOAuthApplicationDataByAppNameResponse struct {
	OAuthApplication OAuthApplicationResponse `xml:"http://org.apache.axis2/xsd return"`
}

// ── OAUTH — REQUEST (marshal) ─────────────────────────────────────────────────

type OAuthApplication struct {
	OAuthVersion                     string           `xml:"xsd1:OAuthVersion"`
	ApplicationAccessTokenExpiryTime int64            `xml:"xsd1:applicationAccessTokenExpiryTime"`
	ApplicationName                  string           `xml:"xsd1:applicationName"`
	Audiences                        []string         `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd audiences"`
	BypassClientCredentials          bool             `xml:"xsd1:bypassClientCredentials"`
	CallbackURL                      string           `xml:"xsd1:callbackUrl"`
	GrantTypes                       string           `xml:"xsd1:grantTypes"`
	OAuthConsumerKey                 string           `xml:"xsd1:oauthConsumerKey,omitempty"`
	OAuthConsumerSecret              string           `xml:"xsd1:oauthConsumerSecret,omitempty"`
	PKCEMandatory                    bool             `xml:"xsd1:pkceMandatory"`
	PKCESupportPlain                 bool             `xml:"xsd1:pkceSupportPlain"`
	RefreshTokenExpiryTime           int64            `xml:"xsd1:refreshTokenExpiryTime"`
	ScopeValidators                  []ScopeValidator `xml:"xsd1:scopeValidators"`
	TokenBindingType                 TokenBindingType `xml:"xsd1:tokenBindingType"`
	UserAccessTokenExpiryTime        int64            `xml:"xsd1:userAccessTokenExpiryTime"`
	IDTokenExpiryTime                int64            `xml:"xsd1:idTokenExpiryTime"`
}

// ── OAUTH — RESPONSE (unmarshal) ──────────────────────────────────────────────

type ScopeValidator string
type TokenBindingType string

const (
	XACMLValidator ScopeValidator   = "Role based scope validator"
	RoleValidator  ScopeValidator   = "XACML Scope Validator"
	SessionBinding TokenBindingType = "sso-session"
	CookieBinding  TokenBindingType = "cookie"
)

type OAuthApplicationResponse struct {
	OAuthVersion                     string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd OAuthVersion"`
	ApplicationAccessTokenExpiryTime int64            `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd applicationAccessTokenExpiryTime"`
	ApplicationName                  string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd applicationName"`
	Audiences                        []string         `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd audiences"`
	BypassClientCredentials          bool             `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd bypassClientCredentials"`
	CallbackURL                      string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd callbackUrl"`
	GrantTypes                       string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd grantTypes"`
	IDTokenExpiryTime                int64            `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd idTokenExpiryTime"`
	OAuthConsumerKey                 string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd oauthConsumerKey"`
	OAuthConsumerSecret              string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd oauthConsumerSecret"`
	PKCEMandatory                    bool             `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd pkceMandatory"`
	PKCESupportPlain                 bool             `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd pkceSupportPlain"`
	RefreshTokenExpiryTime           int64            `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd refreshTokenExpiryTime"`
	ScopeValidators                  []ScopeValidator `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd scopeValidators"`
	TokenBindingType                 TokenBindingType `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd tokenBindingType"`
	TokenType                        string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd tokenType"`
	UserAccessTokenExpiryTime        int64            `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd userAccessTokenExpiryTime"`
	Username                         string           `xml:"http://dto.oauth.identity.carbon.wso2.org/xsd username"`
}
