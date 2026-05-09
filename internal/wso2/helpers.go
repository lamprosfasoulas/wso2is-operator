package wso2

func getLocalAuthenticators(in *[]LocalAuthenticatorConfigResponse) (out []string) {
	if in == nil {
		return
	}
	for _, c := range *in {
		out = append(out, c.Name)
	}
	return
}

func getFederatedIDP(in *[]FederatedIdentityProvidersResponse) string {
	if in == nil || len(*in) == 0 {
		return ""
	}
	return (*in)[0].IdentityProviderName
}
func getFederatedAuthenticator(in *[]FederatedIdentityProvidersResponse) string {
	if in == nil || len(*in) == 0 {
		return ""
	}
	return (*in)[0].FederatedAuthenticatiorConfig[0].Name
}

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
			LocalAuthenticators:    getLocalAuthenticators(&c.LocalAuthenticatorConfigs),
			FederatedIDP:           getFederatedIDP(&c.FederatedIdentityProviders),
			FederatedAuthenticator: getFederatedAuthenticator(&c.FederatedIdentityProviders),
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
		},
		)
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
