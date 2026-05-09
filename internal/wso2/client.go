// Package wso2 defines function to communicate with WSO2IS Server
package wso2

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func NewClient(baseURL, username, password, tenant string, skipTLS bool) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
	}
	return &Client{
		BaseURL:    baseURL,
		Username:   username,
		Password:   password,
		Tenant:     tenant,
		httpClient: &http.Client{Transport: transport},
	}
}

func JSONRequest() RequestOptions {
	return RequestOptions{
		ContentType: ContentTypeJSON,
		Accept:      "application/json",
	}
}
func SOAPRequest(action string) RequestOptions {
	return RequestOptions{
		ContentType: ContentTypeSOAP,
		Accept:      "text/xml",
		SOAPAction:  action,
	}
}

func encodeBody(body any, contentType ContentType) ([]byte, error) {
	switch contentType {
	case ContentTypeSOAP:
		b, err := xml.MarshalIndent(body, "", " ")
		if err != nil {
			return nil, err
		}
		return append([]byte(xml.Header), b...), nil
	case ContentTypeJSON:
		fallthrough
	default:
		return json.Marshal(body)
	}
}

func (c *Client) newRequest(method, path string, body any, opts RequestOptions) (*http.Request, error) {
	var reqBody io.Reader

	if body != nil {
		b, err := encodeBody(body, opts.ContentType)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(b)
		// fmt.Println("Request::BODY::", string(b))
	}
	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.Username, c.Password)

	if opts.ContentType != "" {
		req.Header.Set("Content-Type", string(opts.ContentType))
	}

	if opts.Accept != "" {
		req.Header.Set("Accept", opts.Accept)
	}

	if opts.SOAPAction != "" {
		req.Header.Set("SOAPAction", opts.SOAPAction)
	}

	return req, nil
}

func (c *Client) doRequest(method, path string, body any, opts RequestOptions) (*Response, error) {
	req, err := c.newRequest(method, path, body, opts)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &Response{
		Body:       data,
		StatusCode: resp.StatusCode,
		Location:   resp.Header.Get("Location"),
	}, nil
}

func (c *Client) doJSON(method, path string, reqBody, respBody any) (*Response, error) {
	resp, err := c.doRequest(method, path, reqBody, JSONRequest())
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, fmt.Errorf(
			"http error %d: %s",
			resp.StatusCode,
			string(resp.Body),
		)
	}

	// fmt.Println("JSON::Resp.Body::", string(resp.Body))
	if respBody != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, respBody); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (c *Client) doSOAP(action, path string, reqBody, respBody any) (*Response, error) {
	resp, err := c.doRequest(http.MethodPost, path, reqBody, SOAPRequest(action))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, fmt.Errorf(
			"http error %d: %s",
			resp.StatusCode,
			string(resp.Body),
		)
	}

	// fmt.Println("SOAP::Resp.Body::", string(resp.Body))
	if respBody != nil && len(resp.Body) > 0 {
		if err := xml.Unmarshal(resp.Body, respBody); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// Ping hits /applications?limit=1 just to verify credentials and connectivity
func (c *Client) Ping() error {
	path := fmt.Sprintf("/t/%s/api/server/v1/applications?limit=1", c.Tenant)
	resp, err := c.doJSON("GET", path, nil, nil)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid credentials (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) GetApplicationOAuth2Config(resID, name string) (*OAuth2Config, error) {
	env := RequestEnvelope[GetOAuthBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		Body: GetOAuthBody{
			GetOAuthApplicationDataByAppName: GetOAuthApplicationDataByAppNameRequest{
				AppName: name,
			},
		},
	}

	var data ResponseEnvelope[GetOAuthApplicationDataByAppNameResponseBody]
	resp, err := c.doSOAP("urn:getOAuthApplicationDataByAppName", "/services/OAuthAdminService?wsdl", env, &data)
	if resp.StatusCode == http.StatusInternalServerError {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	oauth2Cfg := data.Body.GetOAuthApplicationDataByAppNameResponse.OAuthApplication
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

func (c *Client) CreateApplicationOAuth2Config(name string, cfg *OAuth2Config) error {
	env := RequestEnvelope[RegisterOAuthBody]{
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
	_, err := c.doSOAP("urn:updateApplication", "/services/OAuthAdminService?wsdl", env, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateApplicationOAuth2Config(name string, cfg *OAuth2Config) error {
	env := RequestEnvelope[UpdateOAuthBody]{
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
	_, err := c.doSOAP("urn:updateApplication", "/services/OAuthAdminService?wsdl", env, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetApplicationByName(name string) (*Application, error) {
	var respJSON map[string]any
	_, err := c.doJSON(http.MethodGet, fmt.Sprintf("/t/%s/api/server/v1/applications?filter=name+eq+%s", c.Tenant, name), nil, &respJSON)
	if err != nil {
		return nil, err
	}

	// fmt.Println(len(respJSON["applications"].([]any)))
	if len(respJSON["applications"].([]any)) == 0 {
		return nil, nil
	}

	env := RequestEnvelope[GetApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		Body: GetApplicationBody{
			GetApplication: GetApplicationRequest{
				ApplicationName: name,
			},
		},
	}
	// fmt.Println("GET::ENV::", env)
	var respEnv ResponseEnvelope[GetApplicationResponseBody]
	_, err = c.doSOAP(http.MethodPost, "/services/IdentityApplicationManagementService?wsdl", env, &respEnv)
	if err != nil {
		// fmt.Println("error here", err)
		return nil, err
	}

	sp := respEnv.Body.GetApplicationResponse.ServiceProvider
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
	}, nil
}

func (c *Client) CreateApplication(sp Application) (*Application, error) {
	env := RequestEnvelope[CreateApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: CreateApplicationBody{
			CreateApplication: CreateApplicationRequest{
				ServiceProvider: ServiceProviderRequest{
					ApplicationName: sp.Name,
					Description:     sp.Description,
				},
			},
		},
	}
	//var data Envelope[GetApplicationResponse]
	_, err := c.doSOAP("urn:createApplication", "/services/IdentityApplicationManagementService?wsdl", env, nil)
	if err != nil {
		return nil, err
	}

	return &Application{}, nil
}

func (c *Client) UpdateApplication(sp Application) error {
	env := RequestEnvelope[UpdateApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: UpdateApplicationBody{
			UpdateApplication: UpdateApplicationRequest{
				ServiceProvider: ServiceProviderRequest{
					ApplicationID:   sp.ID,
					ApplicationName: sp.Name,
					Description:     sp.Description,
					ClaimConfig: &ClaimConfigRequest{
						AlwaysSendMappedLocalSubjectID: "true",
						LocalClaimDialect:              true,
						ClaimMappings:                  buildClaimConfig(sp.Claims),
						UserClaimURI:                   sp.SubjectClaimURI,
					},
					InboundAuthenticationConfig: &InboundAuthenticationConfigRequest{
						InboundAuthenticationRequestConfigs: buildInboundAuthConfig(&sp),
					},
					LocalAndOutboundAuthenticationConfig: buildLocalAndOutboundConfig(&sp),
				},
			},
		},
	}
	_, err := c.doSOAP("urn:updateApplication", "/services/IdentityApplicationManagementService?wsdl", env, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteApplication(spName string) error {
	env := RequestEnvelope[DeleteApplicationBody]{
		SoapEnv: SoapEnvNS,
		XSD:     AxisNS,
		XSD1:    CommonNS,
		Body: DeleteApplicationBody{
			DeleteApplication: DeleteApplicationRequest{
				ApplicationName: spName,
			},
		},
	}
	_, err := c.doSOAP("urn:deleteApplication", "/services/IdentityApplicationManagementService?wsdl", env, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetAdminInfo() (string, string, error) {
	searchJSON := SCIMUserSearch{
		Schemas: []string{
			"urn:ietf:params:scim:api:messages:2.0:SearchRequest",
		},
		Attributes: []string{
			"userName",
		},
		Domain:     "PRIMARY",
		Filter:     "userName eq admin",
		StartIndex: 1,
		Count:      10,
	}
	var data SCIMListResponse[SCIMUser]
	path := fmt.Sprintf("/t/%s/scim2/Users/.search", c.Tenant)
	_, err := c.doJSON("POST", path, searchJSON, &data)
	if err != nil {
		return "", "", fmt.Errorf("scim user search failed: %w", err)
	}
	if len(data.Resources) == 0 {
		return "", "", fmt.Errorf("failed to decode scim response: %w", err)
	}
	return data.Resources[0].Username, data.Resources[0].ID, nil
}

func (c *Client) SetAdminGroupMembership(groupID string) error {
	userName, userID, err := c.GetAdminInfo()
	if err != nil {
		return fmt.Errorf("failed to decode scim response: %w", err)
	}
	if userName == "" || userID == "" {
		return fmt.Errorf("failed to find admin user: %w", err)
	}
	patchJSON := SCIMGroupPatch{
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

	path := fmt.Sprintf("/t/%s/scim2/Groups/%s", c.Tenant, groupID)
	_, err = c.doJSON("PATCH", path, patchJSON, nil)
	if err != nil {
		return fmt.Errorf("scim group patch failed: %w", err)
	}
	return nil
}

func (c *Client) GetAdminGroupMembership(group string) (bool, string, error) {
	searchJSON := SCIMGroupSearch{
		Schemas: []string{
			"urn:ietf:params:scim:api:messages:2.0:SearchRequest",
		},
		StartIndex: 1,
		Filter:     fmt.Sprintf("displayName eq %s", group),
	}
	var groupID string

	var data SCIMListResponse[SCIMGroup]

	path := fmt.Sprintf("/t/%s/scim2/Groups/.search", c.Tenant)
	_, err := c.doJSON("POST", path, searchJSON, &data)
	if err != nil {
		return false, "", fmt.Errorf("scim group search failed: %w", err)
	}
	for _, v := range data.Resources {
		groupID = v.ID
		for _, m := range v.Members {
			if m.Display == "admin" {
				return true, groupID, nil
			}
		}
	}
	if groupID == "" {
		return false, "", fmt.Errorf("group not found")
	}
	return false, groupID, nil
}
