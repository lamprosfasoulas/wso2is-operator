package wso2

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── SAML Metadata XML model ──────────────────────────────────────────────────
//
// We only model the elements we actually need. Unrecognised elements are
// silently ignored by encoding/xml, so additions to the metadata won't break
// parsing.

// xmlBool handles the xs:boolean attribute values "true"/"1"/"false"/"0" that
// encoding/xml cannot unmarshal into a plain bool when they appear as XML
// attributes.
type xmlBool bool

func (b *xmlBool) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var s string
	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	*b = xmlBool(s == "true" || s == "1")
	return nil
}

func (b *xmlBool) UnmarshalXMLAttr(attr xml.Attr) error {
	*b = xmlBool(attr.Value == "true" || attr.Value == "1")
	return nil
}

// ────────────────────────────────────────────────────────────────────────────

type EntityDescriptor struct {
	XMLName  xml.Name `xml:"EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`

	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor"`
}

type IDPSSODescriptor struct {
	WantAuthnRequestsSigned xmlBool `xml:"WantAuthnRequestsSigned,attr"`

	KeyDescriptors       []KeyDescriptor `xml:"KeyDescriptor"`
	NameIDFormats        []string        `xml:"NameIDFormat"`
	SingleSignOnServices []Endpoint      `xml:"SingleSignOnService"`
	SingleLogoutServices []SLOEndpoint   `xml:"SingleLogoutService"`
}

type SPSSODescriptor struct {
	AuthnRequestsSigned  xmlBool `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned xmlBool `xml:"WantAssertionsSigned,attr"`

	KeyDescriptors             []KeyDescriptor             `xml:"KeyDescriptor"`
	NameIDFormats              []string                    `xml:"NameIDFormat"`
	AssertionConsumerServices  []AssertionConsumerService  `xml:"AssertionConsumerService"`
	AttributeConsumingServices []AttributeConsumingService `xml:"AttributeConsumingService"`
	SingleLogoutServices       []SLOEndpoint               `xml:"SingleLogoutService"`
}

type KeyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo KeyInfo `xml:"KeyInfo"`
}

type KeyInfo struct {
	X509Data X509Data `xml:"X509Data"`
}

type X509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type Endpoint struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// SLOEndpoint extends Endpoint with an optional ResponseLocation. When present,
// the SP wants logout responses sent there instead of Location.
type SLOEndpoint struct {
	Binding          string `xml:"Binding,attr"`
	Location         string `xml:"Location,attr"`
	ResponseLocation string `xml:"ResponseLocation,attr"`
}

type AssertionConsumerService struct {
	Binding   string  `xml:"Binding,attr"`
	Location  string  `xml:"Location,attr"`
	Index     int     `xml:"index,attr"`
	IsDefault xmlBool `xml:"isDefault,attr"`
}

type AttributeConsumingService struct {
	Index     int     `xml:"index,attr"`
	IsDefault xmlBool `xml:"isDefault,attr"`
}

// ── Binding constants ────────────────────────────────────────────────────────

const (
	bindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	bindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingHTTPArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	bindingSOAP         = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
)

// ── Public API ───────────────────────────────────────────────────────────────

// FetchSPMetadata fetches SP SAML metadata from url and returns a SAMLConfig
// ready to register the SP in WSO2IS.
//
// Use this when your application publishes its own metadata and you want to
// auto-populate the WSO2IS service provider registration.
func Fetch(ctx context.Context, url string) (*SAMLConfig, error) {
	ed, err := fetchAndParse(ctx, url)
	if err != nil {
		return nil, err
	}
	if ed.SPSSODescriptor == nil {
		return nil, fmt.Errorf("metadata at %s contains no SPSSODescriptor", url)
	}
	return spConfigFromDescriptor(ed.EntityID, ed.SPSSODescriptor), nil
}

// FetchIDPMetadata fetches IdP SAML metadata from url and returns a SAMLConfig
// populated with the fields WSO2IS needs when you are adding this remote IdP
// as a federated identity provider. Fields that only make sense for SP
// registration (ACS URLs, etc.) are left empty.
//
// Note: this returns the same SAMLConfig type for convenience, but only a
// subset of fields is relevant for IdP federation configuration.
func FetchIDPMetadata(ctx context.Context, url string) (*SAMLConfig, error) {
	ed, err := fetchAndParse(ctx, url)
	if err != nil {
		return nil, err
	}
	if ed.IDPSSODescriptor == nil {
		return nil, fmt.Errorf("metadata at %s contains no IDPSSODescriptor", url)
	}
	return idpConfigFromDescriptor(ed.EntityID, ed.IDPSSODescriptor), nil
}

// ParseSPMetadata parses raw SP metadata XML and returns a SAMLConfig.
func ParseSPMetadata(data []byte) (*SAMLConfig, error) {
	ed, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if ed.SPSSODescriptor == nil {
		return nil, fmt.Errorf("metadata contains no SPSSODescriptor")
	}
	return spConfigFromDescriptor(ed.EntityID, ed.SPSSODescriptor), nil
}

// ParseIDPMetadata parses raw IdP metadata XML and returns a SAMLConfig.
func ParseIDPMetadata(data []byte) (*SAMLConfig, error) {
	ed, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if ed.IDPSSODescriptor == nil {
		return nil, fmt.Errorf("metadata contains no IDPSSODescriptor")
	}
	return idpConfigFromDescriptor(ed.EntityID, ed.IDPSSODescriptor), nil
}

// ── SP descriptor → SAMLConfig ───────────────────────────────────────────────

func spConfigFromDescriptor(entityID string, sp *SPSSODescriptor) *SAMLConfig {
	cfg := &SAMLConfig{
		Issuer: entityID,

		// SP metadata signals whether its AuthnRequests are signed.
		// WSO2IS should validate them accordingly.
		DoValidateSignatureInRequests: bool(sp.AuthnRequestsSigned),

		// SP metadata signals whether it wants assertions signed.
		DoSignAssertions: bool(sp.WantAssertionsSigned),

		// Always sign the response — WSO2IS best practice.
		DoSignResponse: true,
	}

	// ── NameID format ────────────────────────────────────────────────────────
	// Take the first declared format; most SPs declare exactly one.
	if len(sp.NameIDFormats) > 0 {
		cfg.NameIDFormat = strings.TrimSpace(sp.NameIDFormats[0])
	}

	// ── Assertion Consumer Services ──────────────────────────────────────────
	acsURLs, defaultACS := collectACSURLs(sp.AssertionConsumerServices)
	cfg.ACSURLs = acsURLs
	cfg.DefaultAssertionConsumerURL = defaultACS

	for _, acs := range sp.AssertionConsumerServices {
		if acs.Binding == bindingHTTPArtifact {
			cfg.EnableSAML2ArtifactBinding = true
			break
		}
	}

	// ── Single Logout Services ───────────────────────────────────────────────
	cfg.DoSingleLogout, cfg.DoFrontChannelLogout,
		cfg.FrontChannelLogoutBinding,
		cfg.SloRequestURL, cfg.SloResponseURL = parseSLOEndpoints(sp.SingleLogoutServices)

	// ── Certificates ─────────────────────────────────────────────────────────
	// "signing"    → SP signs AuthnRequests; WSO2IS needs this cert to verify.
	// "encryption" → SP can receive encrypted assertions.
	// (no use)     → cert serves both purposes.
	for _, kd := range sp.KeyDescriptors {
		raw := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate)
		if raw == "" {
			continue
		}
		use := strings.ToLower(kd.Use)
		switch use {
		case "signing", "":
			if cfg.CertificateContent == "" {
				cfg.CertificateContent = raw
				cfg.CertAlias = deriveAlias(raw, entityID)
			}
		}
		if use == "encryption" || use == "" {
			cfg.DoEnableEncryptedAssertion = true
		}
	}

	// ── AttributeConsumingService ────────────────────────────────────────────
	// WSO2IS auto-generates its own large integer index on registration, so we
	// do NOT map the metadata index to AttributeConsumingServiceIndex.
	// We only use the presence of an AttributeConsumingService element to know
	// that attribute profile should be enabled.
	if len(sp.AttributeConsumingServices) > 0 {
		cfg.EnableAttributeProfile = true
		cfg.EnableAttributesByDefault = true
	}

	return cfg
}

// ── IdP descriptor → SAMLConfig ─────────────────────────────────────────────

func idpConfigFromDescriptor(entityID string, idp *IDPSSODescriptor) *SAMLConfig {
	cfg := &SAMLConfig{
		Issuer: entityID,

		DoValidateSignatureInRequests: bool(idp.WantAuthnRequestsSigned),
		DoSignResponse:                true,
		DoSignAssertions:              true,
	}

	// ── NameID format ────────────────────────────────────────────────────────
	if len(idp.NameIDFormats) > 0 {
		cfg.NameIDFormat = strings.TrimSpace(idp.NameIDFormats[0])
	}

	// ── SSO endpoint → LoginPageURL ──────────────────────────────────────────
	// Prefer HTTP-POST, then HTTP-Redirect.
	for _, ep := range idp.SingleSignOnServices {
		if ep.Binding == bindingHTTPPost {
			cfg.LoginPageURL = ep.Location
			break
		}
	}
	if cfg.LoginPageURL == "" {
		for _, ep := range idp.SingleSignOnServices {
			if ep.Binding == bindingHTTPRedirect {
				cfg.LoginPageURL = ep.Location
				break
			}
		}
	}

	// ── SLO endpoints ────────────────────────────────────────────────────────
	cfg.DoSingleLogout, cfg.DoFrontChannelLogout,
		cfg.FrontChannelLogoutBinding,
		cfg.SloRequestURL, cfg.SloResponseURL = parseSLOEndpoints(idp.SingleLogoutServices)

	// ── Signing certificate ───────────────────────────────────────────────────
	for _, kd := range idp.KeyDescriptors {
		raw := strings.TrimSpace(kd.KeyInfo.X509Data.X509Certificate)
		if raw == "" {
			continue
		}
		use := strings.ToLower(kd.Use)
		if use == "signing" || use == "" {
			cfg.CertificateContent = raw
			cfg.CertAlias = deriveAlias(raw, entityID)
			break
		}
	}

	return cfg
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func fetchAndParse(ctx context.Context, url string) (*EntityDescriptor, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata endpoint returned %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4 MB safety cap
	if err != nil {
		return nil, fmt.Errorf("read metadata body: %w", err)
	}
	return parseXML(data)
}

func parseXML(data []byte) (*EntityDescriptor, error) {
	var ed EntityDescriptor
	if err := xml.Unmarshal(data, &ed); err != nil {
		return nil, fmt.Errorf("parse metadata XML: %w", err)
	}
	if ed.EntityID == "" {
		return nil, fmt.Errorf("metadata is missing required entityID attribute")
	}
	return &ed, nil
}

// collectACSURLs returns all ACS URLs and the best default.
// Priority: explicit isDefault="true" > lowest index.
func collectACSURLs(services []AssertionConsumerService) (urls []string, defaultURL string) {
	if len(services) == 0 {
		return nil, ""
	}

	urls = make([]string, 0, len(services))
	lowestIndex := services[0].Index
	lowestURL := services[0].Location

	for _, acs := range services {
		urls = append(urls, acs.Location)

		if bool(acs.IsDefault) {
			defaultURL = acs.Location
		}
		if acs.Index < lowestIndex {
			lowestIndex = acs.Index
			lowestURL = acs.Location
		}
	}

	if defaultURL == "" {
		defaultURL = lowestURL
	}
	return urls, defaultURL
}

// parseSLOEndpoints extracts SLO configuration from a list of endpoints.
// Returns: doSingleLogout, doFrontChannel, frontChannelBinding, requestURL, responseURL.
func parseSLOEndpoints(endpoints []SLOEndpoint) (
	doSingleLogout bool,
	doFrontChannel bool,
	frontChannelBinding string,
	requestURL string,
	responseURL string,
) {
	if len(endpoints) == 0 {
		return false, false, "", "", ""
	}

	doSingleLogout = true

	// Prefer front-channel (POST > Redirect) over SOAP back-channel.
	for _, ep := range endpoints {
		switch ep.Binding {
		case bindingHTTPPost, bindingHTTPRedirect:
			if !doFrontChannel || ep.Binding == bindingHTTPPost {
				doFrontChannel = true
				frontChannelBinding = ep.Binding
				requestURL = ep.Location
				responseURL = ep.ResponseLocation
				if responseURL == "" {
					responseURL = ep.Location
				}
			}
		case bindingSOAP:
			// Back-channel fallback — only use if no front-channel found yet.
			if requestURL == "" {
				requestURL = ep.Location
				responseURL = ep.Location
			}
		}
	}
	return
}

// deriveAlias produces a short human-readable cert alias.
// WSO2IS uses the alias to look up the cert in its keystore; it does not need
// to match the cert CN exactly, but a meaningful name helps administration.
// We use the entityID host segment as a stable, collision-resistant alias.
func deriveAlias(certB64, entityID string) string {
	// Extract the hostname from the entity ID (which is usually a URL or URN).
	// e.g. "https://myapp.example.com/saml" → "myapp.example.com"
	s := entityID
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	// Strip port.
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		s = s[:idx]
	}
	if s != "" {
		return s
	}
	// Absolute fallback: first 16 chars of the raw cert.
	if len(certB64) > 16 {
		return certB64[:16]
	}
	return certB64
}
