package wso2

type Claim struct {
	URI       string `json:"uri"`
	Mandatory bool   `json:"mandatory"`
}

type OAuth2Config struct {
	Enabled     bool     `json:"enabled"`
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

type SAMLConfig struct {
	Enabled                bool     `json:"enabled"`
	ACSURLs                []string `json:"acsURLs,omitempty"`
	RequestedAudiences     []string `json:"requestedAudiences,omitempty"`
	RequestedRecipients    []string `json:"requestedRecipients,omitempty"`
	IdpInitSLOReturnToURLs []string `json:"idpInitSLOReturnToURLs,omitempty"`

	Issuer                      string `json:"issuer,omitempty"`
	IssuerQualifier             string `json:"issuerQualifier,omitempty"`
	DefaultAssertionConsumerURL string `json:"defaultAssertionConsumerURL,omitempty"`
	NameIDFormat                string `json:"nameIDFormat,omitempty"`
	NameIDClaimURI              string `json:"nameIDClaimUri,omitempty"`
	CertAlias                   string `json:"certAlias,omitempty"`
	CertificateContent          string `json:"certificateContent,omitempty"`
	LoginPageURL                string `json:"loginPageURL,omitempty"`
	IdpEntityIDAlias            string `json:"idpEntityIDAlias,omitempty"`

	SigningAlgorithmURI             string `json:"signingAlgorithmURI,omitempty"`
	DigestAlgorithmURI              string `json:"digestAlgorithmURI,omitempty"`
	AssertionEncryptionAlgorithmURI string `json:"assertionEncryptionAlgorithmURI,omitempty"`
	KeyEncryptionAlgorithmURI       string `json:"keyEncryptionAlgorithmURI,omitempty"`

	SloRequestURL             string `json:"sloRequestURL,omitempty"`
	SloResponseURL            string `json:"sloResponseURL,omitempty"`
	FrontChannelLogoutBinding string `json:"frontChannelLogoutBinding,omitempty"`

	AttributeConsumingServiceIndex      string `json:"attributeConsumingServiceIndex,omitempty"`
	SupportedAssertionQueryRequestTypes string `json:"supportedAssertionQueryRequestTypes,omitempty"`

	DoSignAssertions                     bool `json:"doSignAssertions,omitempty"`
	DoSignResponse                       bool `json:"doSignResponse,omitempty"`
	DoSingleLogout                       bool `json:"doSingleLogout,omitempty"`
	DoFrontChannelLogout                 bool `json:"doFrontChannelLogout,omitempty"`
	DoEnableEncryptedAssertion           bool `json:"doEnableEncryptedAssertion,omitempty"`
	DoValidateSignatureInRequests        bool `json:"doValidateSignatureInRequests,omitempty"`
	DoValidateSignatureInArtifactResolve bool `json:"doValidateSignatureInArtifactResolve,omitempty"`
	EnableAttributeProfile               bool `json:"enableAttributeProfile,omitempty"`
	EnableAttributesByDefault            bool `json:"enableAttributesByDefault,omitempty"`
	EnableSAML2ArtifactBinding           bool `json:"enableSAML2ArtifactBinding,omitempty"`
	AssertionQueryRequestProfileEnabled  bool `json:"assertionQueryRequestProfileEnabled,omitempty"`
	IDPInitSSOEnabled                    bool `json:"iDPInitSSOEnabled,omitempty"`
	IDPInitSLOEnabled                    bool `json:"iDPInitSLOEnabled,omitempty"`
	SamlECP                              bool `json:"samlECP,omitempty"`
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
	SAML                 *SAMLConfig          `json:"saml"`
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
