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
)

type ContentType string
type SOAPAction string
type SOAPEndpoint string

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

type RequestOptions struct {
	ContentType ContentType
	Accept      string
	SOAPAction  SOAPAction
}

const (
	ContentTypeJSON ContentType = "application/json"
	ContentTypeSOAP ContentType = "text/xml; charset=utf-8"

	applicationEndpoint SOAPEndpoint = "/services/IdentityApplicationManagementService?wsdl"
	oAuthEndpoint       SOAPEndpoint = "/services/OAuthAdminService?wsdl"
	samlEndpoint        SOAPEndpoint = "/services/IdentitySAMLSSOConfigService?wsdl"

	getApplication        SOAPAction = "urn:getApplication"
	createApplication     SOAPAction = "urn:createApplication"
	deleteApplication     SOAPAction = "urn:deleteApplication"
	updateApplication     SOAPAction = "urn:updateApplication"
	getOAuthApplication   SOAPAction = "urn:getOAuthApplicationDataByAppName"
	getSAMLApplication    SOAPAction = "urn:getServiceProvider"
	createSAMLApplication SOAPAction = "urn:addRPServiceProvider"
	removeSAMLApplication SOAPAction = "urn:removeServiceProvider"
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

func jsonRequest() RequestOptions {
	return RequestOptions{
		ContentType: ContentTypeJSON,
		Accept:      "application/json",
	}
}
func soapRequest(action SOAPAction) RequestOptions {
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
		req.Header.Set("SOAPAction", string(opts.SOAPAction))
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

	defer func() {
		_ = resp.Body.Close()
	}()

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
	resp, err := c.doRequest(method, path, reqBody, jsonRequest())
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

func (c *Client) doSOAP(action SOAPAction, path SOAPEndpoint, reqBody, respBody any) (*Response, error) {
	resp, err := c.doRequest(http.MethodPost, string(path), reqBody, soapRequest(action))
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

func (c *Client) getUserInfo(name string) (string, string, error) {
	path := fmt.Sprintf("/t/%s/scim2/Users/.search", c.Tenant)
	request := buildUserSearch(name)
	var response SCIMListResponse[SCIMUser]
	_, err := c.doJSON("POST", path, request, &response)
	if err != nil {
		return "", "", fmt.Errorf("scim user search failed: %w", err)
	}
	if len(response.Resources) == 0 {
		return "", "", fmt.Errorf("failed to decode scim response: %w", err)
	}
	return response.Resources[0].Username, response.Resources[0].ID, nil
}

func (c *Client) joinUserToGroup(userName, groupID string) error {
	path := fmt.Sprintf("/t/%s/scim2/Groups/%s", c.Tenant, groupID)
	username, userID, err := c.getUserInfo(userName)
	if err != nil {
		return fmt.Errorf("failed to decode scim response: %w", err)
	}
	if username == "" || userID == "" {
		return fmt.Errorf("failed to find admin user: %w", err)
	}
	request := buildJoinUserToGroup(username, userID)
	_, err = c.doJSON("PATCH", path, request, nil)
	if err != nil {
		return fmt.Errorf("scim group patch failed: %w", err)
	}
	return nil
}

func (c *Client) JoinAdminToGroup(groupID string) error {
	return c.joinUserToGroup("admin", groupID)
}

func getUserGroupMembership(userName string, group *SCIMGroup) bool {
	for _, m := range group.Members {
		if m.Display == userName {
			return true
		}
	}
	return false
}

func (c *Client) getGroupInfo(groupName string) (*SCIMGroup, error) {
	path := fmt.Sprintf("/t/%s/scim2/Groups/.search", c.Tenant)

	request := buildGroupSearch(groupName)
	var response SCIMListResponse[SCIMGroup]
	_, err := c.doJSON("POST", path, request, &response)
	if err != nil {
		return nil, fmt.Errorf("scim group search failed: %w", err)
	}
	if len(response.Resources) == 0 || len(response.Resources) > 1 {
		return nil, fmt.Errorf("scim group search failed: ")
	}
	return &response.Resources[0], nil
}

func (c *Client) GetAdminGroupMembership(groupName string) (bool, string, error) {
	groupInfo, err := c.getGroupInfo(groupName)
	if err != nil {
		return false, "", err
	}
	if groupInfo == nil {
		return false, "", fmt.Errorf("group %s does not exist", groupName)
	}
	adminJoined := getUserGroupMembership("admin", groupInfo)
	return adminJoined, (*groupInfo).ID, nil
}

func (c *Client) GetApplicationOAuth2Config(resID, name string) (*OAuth2Config, error) {
	request := buildGetOAuthApplication(name)

	var response ResponseEnvelope[GetOAuthApplicationDataByAppNameResponseBody]
	resp, err := c.doSOAP(getOAuthApplication, oAuthEndpoint, request, &response)
	if resp.StatusCode == http.StatusInternalServerError {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return mapGetOAuthApplication(&response)
}

func (c *Client) CreateApplicationOAuth2Config(name string, cfg *OAuth2Config) error {
	request := buildCreateOAuthApplicaiton(name, cfg)
	_, err := c.doSOAP(updateApplication, oAuthEndpoint, request, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateApplicationOAuth2Config(name string, cfg *OAuth2Config) error {
	request := buildUpdateOAuthApplication(name, cfg)
	_, err := c.doSOAP(updateApplication, oAuthEndpoint, request, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) GetApplicationSAMLConfig(issuer string) (*SAMLConfig, error) {
	request := buildGetSAMLApplication(issuer)
	var response ResponseEnvelope[GetSAMLSPResponseBody]
	_, err := c.doSOAP(getSAMLApplication, samlEndpoint, request, &response)
	if err != nil {
		return nil, err
	}
	if response.Body.Response.Return == nil {
		return nil, nil
	}
	return mapSAMLApplication(&response)
}

func (c *Client) CreateSAMLApplication(cfg *SAMLConfig) error {
	request := buildCreateSAMLApplication(cfg)
	_, err := c.doSOAP(createSAMLApplication, samlEndpoint, request, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) UpdateSAMLApplication(cfg *SAMLConfig) error {
	if err := c.DeleteApplication(cfg.Issuer); err != nil {
		return err
	}
	if err := c.CreateSAMLApplication(cfg); err != nil {
		return err
	}
	return nil
}

func (c *Client) RemoveSAMLApplication(issuer string) error {
	request := buildRemoveSAMLAPplication(issuer)
	_, err := c.doSOAP(removeSAMLApplication, samlEndpoint, request, nil)
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

	request := buildGetApplication(name)
	// fmt.Println("GET::ENV::", env)
	var response ResponseEnvelope[GetApplicationResponseBody]
	_, err = c.doSOAP(getApplication, applicationEndpoint, request, &response)
	if err != nil {
		// fmt.Println("error here", err)
		return nil, err
	}
	return mapGetApplication(&response)
}

func (c *Client) CreateApplication(a Application) (*Application, error) {
	request := buildCreateApplication(&a)
	_, err := c.doSOAP(createApplication, applicationEndpoint, request, nil)
	if err != nil {
		return nil, err
	}

	return &Application{}, nil
}

func (c *Client) UpdateApplication(a Application) error {
	request := buildUpdateApplication(&a)
	_, err := c.doSOAP(updateApplication, applicationEndpoint, request, nil)
	if err != nil {
		return err
	}
	return nil
}

func (c *Client) DeleteApplication(spName string) error {
	request := buildDeleteApplication(spName)
	_, err := c.doSOAP(deleteApplication, applicationEndpoint, request, nil)
	if err != nil {
		return err
	}
	return nil
}
