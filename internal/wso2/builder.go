package wso2

import (
	"fmt"
	"strings"
)

func buildClaimConfig(claims []Claim) []ClaimMappingRequest {
	if len(claims) == 0 {
		return nil
	}
	mappings := make([]ClaimMappingRequest, 0, len(claims))
	for _, c := range claims {
		mappings = append(mappings, ClaimMappingRequest{
			LocalClaim: ClaimRequest{
				ClaimURI: c.URI,
			},
			RemoteClaim: ClaimRequest{
				ClaimURI: c.URI,
			},
			Mandatory: c.Mandatory,
			Requested: true,
		})
	}
	return mappings
}

func buildScopeValidators(in []string) (out []ScopeValidator) {
	if len(in) == 0 {
		return
	}
	for _, c := range in {
		switch c {
		case "xacml":
			out = append(out, XACMLValidator)
		case "role":
			out = append(out, RoleValidator)
		}
	}
	return
}

func buildTokenBindingType(in string) (out TokenBindingType) {
	if in == "" {
		return
	}
	switch in {
	case "session":
		out = SessionBinding
	case "cookie":
		out = CookieBinding
	}
	return
}

func buildInboundAuthConfig(sp *Application) (configs []InboundAuthenticationRequestConfigRequest) {
	if sp.OAuth2 != nil {
		configs = append(configs, InboundAuthenticationRequestConfigRequest{
			InboundAuthKey:  sp.OAuth2.OAuthConsumerKey,
			InboundAuthType: "oauth2",
			Properties: []PropertyRequest{
				{
					Name:  "oauthConsumerSecret",
					Value: sp.OAuth2.OAuthConsumerSecret,
				},
			},
		})
	}
	if sp.SAML != nil {
		configs = append(configs, InboundAuthenticationRequestConfigRequest{
			InboundAuthKey:  sp.SAML.Issuer,
			InboundAuthType: "samlsso",
			Properties: []PropertyRequest{
				{
					Name:  "attrConsumServiceIndex",
					Value: sp.SAML.AttributeConsumingServiceIndex,
				},
			},
		})
	}
	configs = append(configs, InboundAuthenticationRequestConfigRequest{
		InboundAuthKey:  sp.Name,
		InboundAuthType: "openid",
	},
	)
	configs = append(configs, InboundAuthenticationRequestConfigRequest{
		InboundAuthKey:  sp.Name,
		InboundAuthType: "passivests",
	},
	)
	return
}

func buildLocalAuthenticators(la []string) (locals []LocalAuthenticatorConfigRequest) {
	for _, c := range la {
		locals = append(locals, LocalAuthenticatorConfigRequest{
			Name:  c,
			Valid: true,
		})
	}
	return
}

func buildFederatedAuthenticators(st AuthenticationStep) (feds []FederatedAuthenticatiorConfigRequest) {
	if st.FederatedAuthenticator == "" {
		return nil
	}
	return []FederatedAuthenticatiorConfigRequest{
		{
			Name:  st.FederatedAuthenticator,
			Valid: true,
		},
	}
}

func buildAuthenticationSteps(sp *Application) (steps []AuthenticationStepRequest) {
	if sp.AuthenticationSteps == nil {
		return
	}
	for _, c := range sp.AuthenticationSteps {
		step := AuthenticationStepRequest{
			LocalAuthenticatorConfigs: buildLocalAuthenticators(c.LocalAuthenticators),
			StepOrder:                 c.Step,
			SubjectStep:               sp.StepForSubject == c.Step,
			AttributeStep:             sp.StepForAttributes == c.Step,
		}

		if feds := buildFederatedAuthenticators(c); len(feds) > 0 || c.FederatedIDP != "" {
			step.FederatedIdentityProviders = &[]FederatedIdentityProvidersRequest{
				{
					FederatedAuthenticatiorConfig: feds,
					IdentityProviderName:          c.FederatedIDP,
				},
			}
		}
		steps = append(steps, step)
	}
	return
}
func buildAuthenticationScriptConfig(sp *Application) (sc AuthenticationScriptConfigRequest) {
	if sp.AuthenticationScript == "" {
		return AuthenticationScriptConfigRequest{}
	}
	return AuthenticationScriptConfigRequest{
		Content:  sp.AuthenticationScript,
		Language: "application/javascript",
		Enabled:  true,
	}
}

func buildLocalAndOutboundConfig(sp *Application) (config *LocalAndOutboundAuthenticationConfigRequest) {
	config = &LocalAndOutboundAuthenticationConfigRequest{
		AuthenticationType:         "flow",
		SubjectClaimURI:            sp.SubjectClaimURI,
		AuthenticationSteps:        buildAuthenticationSteps(sp),
		AuthenticationScriptConfig: buildAuthenticationScriptConfig(sp),

		AlwaysSendBackAuthenticatedListOfIDPs:      sp.AlwaysSendBackAuthenticatedListOfIDPs,
		EnableAuthorization:                        sp.EnableAuthorization,
		SkipConsent:                                sp.SkipConsent,
		SkipLogoutConsent:                          sp.SkipLogoutConsent,
		UseTenantDomainInLocalSubjectIdentifier:    sp.UseTenantInSub,
		UseUserstoreDomainInLocalSubjectIdentifier: sp.UseUserstoreInSub,
		UseUserstoreDomainInRoles:                  sp.UseUserstoreInRoles,
	}
	return
}

func buildGetOAuthApplication(name string) RequestEnvelope[GetOAuthBody] {
	return RequestEnvelope[GetOAuthBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		Body: GetOAuthBody{
			GetOAuthApplicationDataByAppName: GetOAuthApplicationDataByAppNameRequest{
				AppName: name,
			},
		},
	}
}

func buildCreateOAuthApplicaiton(name string, cfg *OAuth2Config) RequestEnvelope[RegisterOAuthBody] {
	return RequestEnvelope[RegisterOAuthBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: RegisterOAuthBody{
			RegisterOAuthApplicationData: RegisterOAuthApplicationDataRequest{
				Application: OAuthApplication{
					OAuthVersion:                     "OAuth-2.0",
					ApplicationAccessTokenExpiryTime: int64(cfg.AccessTokenExpiry),
					ApplicationName:                  name,
					CallbackURL:                      cfg.CallbackURL,
					GrantTypes:                       strings.Join(cfg.GrantTypes, " "),
					PKCEMandatory:                    cfg.PKCEMandatory,
					PKCESupportPlain:                 cfg.PKCEPlain,
					Audiences:                        cfg.Audiences,
					ScopeValidators:                  buildScopeValidators(cfg.ScopeValidators),
					TokenBindingType:                 buildTokenBindingType(cfg.TokenBinding),
					RefreshTokenExpiryTime:           int64(cfg.RefreshTokenExpiry),
					UserAccessTokenExpiryTime:        int64(cfg.AccessTokenExpiry),
					OAuthConsumerKey:                 cfg.OAuthConsumerKey,
					OAuthConsumerSecret:              cfg.OAuthConsumerSecret,
				},
			},
		},
	}
}

func buildUpdateOAuthApplication(name string, cfg *OAuth2Config) RequestEnvelope[UpdateOAuthBody] {
	return RequestEnvelope[UpdateOAuthBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: UpdateOAuthBody{
			UpdateConsumerApplication: UpdateConsumerApplicationRequest{
				ConsumerAppDTO: OAuthApplication{
					OAuthVersion:                     "OAuth-2.0",
					ApplicationAccessTokenExpiryTime: int64(cfg.AccessTokenExpiry),
					ApplicationName:                  name,
					CallbackURL:                      cfg.CallbackURL,
					GrantTypes:                       strings.Join(cfg.GrantTypes, " "),
					PKCEMandatory:                    cfg.PKCEMandatory,
					PKCESupportPlain:                 cfg.PKCEPlain,
					Audiences:                        cfg.Audiences,
					ScopeValidators:                  buildScopeValidators(cfg.ScopeValidators),
					TokenBindingType:                 buildTokenBindingType(cfg.TokenBinding),
					RefreshTokenExpiryTime:           int64(cfg.RefreshTokenExpiry),
					UserAccessTokenExpiryTime:        int64(cfg.AccessTokenExpiry),
					OAuthConsumerKey:                 cfg.OAuthConsumerKey,
					OAuthConsumerSecret:              cfg.OAuthConsumerSecret,
				},
			},
		},
	}
}

func buildGetSAMLApplication(issuer string) RequestEnvelope[GetServiceProviderBody] {
	return RequestEnvelope[GetServiceProviderBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		Body: GetServiceProviderBody{
			GetServiceProvider: GetServiceProviderRequest{
				Issuer: issuer,
			},
		},
	}
}

func buildCreateSAMLApplication(cfg *SAMLConfig) RequestEnvelope[CreateSAMLApplicationBody] {
	return RequestEnvelope[CreateSAMLApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: CreateSAMLApplicationBody{
			CreateSAMLApplicationRequest: CreateSAMLApplicationRequest{
				SpDto: SAMLSSOServiceProviderDTORequest{
					AssertionConsumerUrls:  cfg.ACSURLs,
					RequestedAudiences:     cfg.RequestedAudiences,
					RequestedRecipients:    cfg.RequestedRecipients,
					IdpInitSLOReturnToURLs: cfg.IdpInitSLOReturnToURLs,

					Issuer:                      cfg.Issuer,
					IssuerQualifier:             cfg.IssuerQualifier,
					DefaultAssertionConsumerURL: cfg.DefaultAssertionConsumerURL,
					NameIDFormat:                cfg.NameIDFormat,
					//NameIDClaimUri:              cfg.NameIDClaimUri,
					CertAlias:          cfg.CertAlias,
					CertificateContent: cfg.CertificateContent,
					LoginPageURL:       cfg.LoginPageURL,
					IdpEntityIDAlias:   cfg.IdpEntityIDAlias,

					SigningAlgorithmURI:             cfg.SigningAlgorithmURI,
					DigestAlgorithmURI:              cfg.DigestAlgorithmURI,
					AssertionEncryptionAlgorithmURI: cfg.AssertionEncryptionAlgorithmURI,
					KeyEncryptionAlgorithmURI:       cfg.KeyEncryptionAlgorithmURI,

					SloRequestURL:             cfg.SloRequestURL,
					SloResponseURL:            cfg.SloResponseURL,
					FrontChannelLogoutBinding: cfg.FrontChannelLogoutBinding,

					AttributeConsumingServiceIndex:      cfg.AttributeConsumingServiceIndex,
					SupportedAssertionQueryRequestTypes: cfg.SupportedAssertionQueryRequestTypes,

					DoSignAssertions:                     cfg.DoSignAssertions,
					DoSignResponse:                       cfg.DoSignResponse,
					DoSingleLogout:                       cfg.DoSingleLogout,
					DoFrontChannelLogout:                 cfg.DoFrontChannelLogout,
					DoEnableEncryptedAssertion:           cfg.DoEnableEncryptedAssertion,
					DoValidateSignatureInRequests:        cfg.DoValidateSignatureInRequests,
					DoValidateSignatureInArtifactResolve: cfg.DoValidateSignatureInArtifactResolve,
					EnableAttributeProfile:               cfg.EnableAttributeProfile,
					EnableAttributesByDefault:            cfg.EnableAttributesByDefault,
					EnableSAML2ArtifactBinding:           cfg.EnableSAML2ArtifactBinding,
					AssertionQueryRequestProfileEnabled:  cfg.AssertionQueryRequestProfileEnabled,
					IDPInitSSOEnabled:                    cfg.IDPInitSSOEnabled,
					IDPInitSLOEnabled:                    cfg.IDPInitSLOEnabled,
					SamlECP:                              cfg.SamlECP,
				},
			},
		},
	}
}

func buildRemoveSAMLAPplication(issuer string) RequestEnvelope[RemoveSAMLSPBody] {
	return RequestEnvelope[RemoveSAMLSPBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: RemoveSAMLSPBody{
			RemoveServiceProvider: RemoveServiceProviderRequest{
				Issuer: issuer,
			},
		},
	}
}

func buildGetApplication(name string) RequestEnvelope[GetApplicationBody] {
	return RequestEnvelope[GetApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		Body: GetApplicationBody{
			GetApplication: GetApplicationRequest{
				ApplicationName: name,
			},
		},
	}
}

func buildCreateApplication(in *Application) RequestEnvelope[CreateApplicationBody] {
	return RequestEnvelope[CreateApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: CreateApplicationBody{
			CreateApplication: CreateApplicationRequest{
				ServiceProvider: ServiceProviderRequest{
					ApplicationName: in.Name,
					Description:     in.Description,
				},
			},
		},
	}
}

func buildUpdateApplication(in *Application) RequestEnvelope[UpdateApplicationBody] {
	return RequestEnvelope[UpdateApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: UpdateApplicationBody{
			UpdateApplication: UpdateApplicationRequest{
				ServiceProvider: ServiceProviderRequest{
					ApplicationID:   in.ID,
					ApplicationName: in.Name,
					Description:     in.Description,
					ClaimConfig: &ClaimConfigRequest{
						AlwaysSendMappedLocalSubjectID: "true",
						LocalClaimDialect:              true,
						ClaimMappings:                  buildClaimConfig(in.Claims),
						UserClaimURI:                   in.SubjectClaimURI,
					},
					InboundAuthenticationConfig: &InboundAuthenticationConfigRequest{
						InboundAuthenticationRequestConfigs: buildInboundAuthConfig(in),
					},
					LocalAndOutboundAuthenticationConfig: buildLocalAndOutboundConfig(in),
				},
			},
		},
	}
}

func buildDeleteApplication(name string) RequestEnvelope[DeleteApplicationBody] {
	return RequestEnvelope[DeleteApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: DeleteApplicationBody{
			DeleteApplication: DeleteApplicationRequest{
				ApplicationName: name,
			},
		},
	}
}

func buildUserSearch(user string) SCIMUserSearch {
	return SCIMUserSearch{
		Schemas: []string{
			"urn:ietf:params:scim:api:messages:2.0:SearchRequest",
		},
		Attributes: []string{
			"userName",
		},
		Domain:     "PRIMARY",
		Filter:     fmt.Sprintf("userName eq %s", user),
		StartIndex: 1,
		Count:      10,
	}
}

func buildJoinUserToGroup(userName, userID string) SCIMGroupPatch {
	return SCIMGroupPatch{
		Schemas: []string{
			"urn:ietf:params:scim:api:messages:2.0:PatchOp",
		},
		Operations: []SCIMPatchOperation{
			{
				Op: "add",
				Value: SCIMPatchMembers{
					Members: []SCIMPatchMember{
						{
							Display: userName,
							Value:   userID,
						},
					},
				},
			},
		},
	}
}

func buildGroupSearch(name string) SCIMGroupSearch {
	return SCIMGroupSearch{
		Schemas: []string{
			"urn:ietf:params:scim:api:messages:2.0:SearchRequest",
		},
		StartIndex: 1,
		Filter:     fmt.Sprintf("displayName eq %s", name),
	}
}
