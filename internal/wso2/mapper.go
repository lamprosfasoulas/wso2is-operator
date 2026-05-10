package wso2

import "strings"

func mapTokenBinding(in TokenBindingType) (out string) {
	if in == "" {
		return
	}
	switch in {
	case SessionBinding:
		out = "session"
	case CookieBinding:
		out = "cookie"
	default:
	}
	return
}

func mapScopeValidators(in []ScopeValidator) (out []string) {
	if len(in) == 0 {
		return
	}

	for _, c := range in {
		switch c {
		case XACMLValidator:
			out = append(out, "xacml")
		case RoleValidator:
			out = append(out, "role")
		default:
		}
	}
	return
}

func mapLocalAuthenticators(in *[]LocalAuthenticatorConfigResponse) (out []string) {
	if in == nil {
		return
	}
	for _, c := range *in {
		out = append(out, c.Name)
	}
	return
}

func mapFederatedIDP(in *[]FederatedIdentityProvidersResponse) string {
	if in == nil || len(*in) == 0 {
		return ""
	}
	return (*in)[0].IdentityProviderName
}
func mapFederatedAuthenticator(in *[]FederatedIdentityProvidersResponse) string {
	if in == nil || len(*in) == 0 {
		return ""
	}
	return (*in)[0].FederatedAuthenticatiorConfig[0].Name
}

func mapAuthenticationSteps(in []AuthenticationStepResponse) (steps []AuthenticationStep, sub, attr int) {
	if len(in) == 0 {
		return nil, 1, 1
	}
	for _, c := range in {
		if c.SubjectStep {
			sub = c.StepOrder
		}
		if c.AttributeStep {
			attr = c.StepOrder
		}
		steps = append(steps, AuthenticationStep{
			Step:                   c.StepOrder,
			LocalAuthenticators:    mapLocalAuthenticators(&c.LocalAuthenticatorConfigs),
			FederatedIDP:           mapFederatedIDP(&c.FederatedIdentityProviders),
			FederatedAuthenticator: mapFederatedAuthenticator(&c.FederatedIdentityProviders),
		})
	}
	return
}

func mapClaims(in []ClaimMappingResponse) []Claim {
	if len(in) == 0 {
		return nil
	}
	out := make([]Claim, 0, len(in))
	for _, c := range in {
		out = append(out, Claim{
			URI:       c.LocalClaim.ClaimURI,
			Mandatory: c.Mandatory,
		})
	}
	return out
}

func isOAuthEnalbed(in *[]InboundAuthenticationRequestConfigResponse) bool {
	for _, v := range *in {
		if v.InboundAuthType == "oauth2" {
			return true
		}
	}
	return false
}

func isSAMLEnabled(in *[]InboundAuthenticationRequestConfigResponse) bool {
	for _, v := range *in {
		if v.InboundAuthType == "samlsso" {
			return true
		}
	}
	return false
}

func mapGetApplication(in *ResponseEnvelope[GetApplicationResponseBody]) (*Application, error) {
	sp := in.Body.GetApplicationResponse.ServiceProvider
	lab := sp.LocalAndOutboundAuthenticationConfig

	steps, sub, attr := mapAuthenticationSteps(sp.LocalAndOutboundAuthenticationConfig.AuthenticationSteps)

	return &Application{
		ID:                   sp.ApplicationID,
		ResourceID:           sp.ApplicationResourceID,
		Name:                 sp.ApplicationName,
		Description:          sp.Description,
		Claims:               mapClaims(sp.ClaimConfig.ClaimMappings),
		SubjectClaimURI:      lab.SubjectClaimURI,
		AuthenticationSteps:  steps,
		AuthenticationScript: lab.AuthenticationScriptConfig.Content,

		EnableAuthorization: lab.EnableAuthorization,
		SkipConsent:         lab.SkipConsent,
		SkipLogoutConsent:   lab.SkipLogoutConsent,
		UseTenantInSub:      lab.UseTenantDomainInLocalSubjectIdentifier,
		UseUserstoreInSub:   lab.UseUserstoreDomainInLocalSubjectIdentifier,
		UseUserstoreInRoles: lab.UseUserstoreDomainInRoles,

		StepForSubject:    sub,
		StepForAttributes: attr,
		OAuth2: &OAuth2Config{
			Enabled: isOAuthEnalbed(&sp.InboundAuthenticationConfig.InboundAuthenticationRequestConfigs),
		},
		SAML: &SAMLConfig{
			Enabled: isSAMLEnabled(&sp.InboundAuthenticationConfig.InboundAuthenticationRequestConfigs),
		},
	}, nil
}

func mapGetOAuthApplication(in *ResponseEnvelope[GetOAuthApplicationDataByAppNameResponseBody]) (*OAuth2Config, error) {
	oauth2Cfg := in.Body.GetOAuthApplicationDataByAppNameResponse.OAuthApplication
	// fmt.Println("Got::OAUTH2::", oauth2Cfg.CallbackURL)
	return &OAuth2Config{
		CallbackURL:         oauth2Cfg.CallbackURL,
		GrantTypes:          strings.Split(oauth2Cfg.GrantTypes, " "),
		PKCEMandatory:       oauth2Cfg.PKCEMandatory,
		PKCEPlain:           oauth2Cfg.PKCESupportPlain,
		PublicClient:        oauth2Cfg.BypassClientCredentials,
		TokenBinding:        mapTokenBinding(oauth2Cfg.TokenBindingType),
		Audiences:           oauth2Cfg.Audiences,
		ScopeValidators:     mapScopeValidators(oauth2Cfg.ScopeValidators),
		AccessTokenExpiry:   int(oauth2Cfg.UserAccessTokenExpiryTime),
		RefreshTokenExpiry:  int(oauth2Cfg.RefreshTokenExpiryTime),
		OAuthConsumerKey:    oauth2Cfg.OAuthConsumerKey,
		OAuthConsumerSecret: oauth2Cfg.OAuthConsumerSecret,
	}, nil
}

func mapSAMLApplication(in *ResponseEnvelope[GetSAMLSPResponseBody]) (*SAMLConfig, error) {
	samlCfg := in.Body.Response.Return
	return &SAMLConfig{
		ACSURLs:                samlCfg.AssertionConsumerUrls,
		RequestedAudiences:     samlCfg.RequestedAudiences,
		RequestedRecipients:    samlCfg.RequestedRecipients,
		IdpInitSLOReturnToURLs: samlCfg.IdpInitSLOReturnToURLs,

		Issuer:                      samlCfg.Issuer,
		IssuerQualifier:             samlCfg.IssuerQualifier,
		DefaultAssertionConsumerURL: samlCfg.DefaultAssertionConsumerURL,
		NameIDFormat:                samlCfg.NameIDFormat,
		// NameIDClaimUri:              samlCfg.NameIDClaimUri,
		CertAlias:          samlCfg.CertAlias,
		CertificateContent: samlCfg.CertificateContent,
		LoginPageURL:       samlCfg.LoginPageURL,
		IdpEntityIDAlias:   samlCfg.IdpEntityIDAlias,

		SigningAlgorithmURI:             samlCfg.SigningAlgorithmURI,
		DigestAlgorithmURI:              samlCfg.DigestAlgorithmURI,
		AssertionEncryptionAlgorithmURI: samlCfg.AssertionEncryptionAlgorithmURI,
		KeyEncryptionAlgorithmURI:       samlCfg.KeyEncryptionAlgorithmURI,

		SloRequestURL:             samlCfg.SloRequestURL,
		SloResponseURL:            samlCfg.SloResponseURL,
		FrontChannelLogoutBinding: samlCfg.FrontChannelLogoutBinding,

		AttributeConsumingServiceIndex:      samlCfg.AttributeConsumingServiceIndex,
		SupportedAssertionQueryRequestTypes: samlCfg.SupportedAssertionQueryRequestTypes,

		DoSignAssertions:                     samlCfg.DoSignAssertions,
		DoSignResponse:                       samlCfg.DoSignResponse,
		DoSingleLogout:                       samlCfg.DoSingleLogout,
		DoFrontChannelLogout:                 samlCfg.DoFrontChannelLogout,
		DoEnableEncryptedAssertion:           samlCfg.DoEnableEncryptedAssertion,
		DoValidateSignatureInRequests:        samlCfg.DoValidateSignatureInRequests,
		DoValidateSignatureInArtifactResolve: samlCfg.DoValidateSignatureInArtifactResolve,
		EnableAttributeProfile:               samlCfg.EnableAttributeProfile,
		EnableAttributesByDefault:            samlCfg.EnableAttributesByDefault,
		EnableSAML2ArtifactBinding:           samlCfg.EnableSAML2ArtifactBinding,
		AssertionQueryRequestProfileEnabled:  samlCfg.AssertionQueryRequestProfileEnabled,
		IDPInitSSOEnabled:                    samlCfg.IDPInitSSOEnabled,
		IDPInitSLOEnabled:                    samlCfg.IDPInitSLOEnabled,
		SamlECP:                              samlCfg.SamlECP,
	}, nil
}
