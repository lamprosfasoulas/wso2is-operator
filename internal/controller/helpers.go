package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	wso2v1alpha1 "github.com/lamprosfasoulas/wso2is-operator/api/v1alpha1"
	"github.com/lamprosfasoulas/wso2is-operator/internal/wso2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Component string

const (
	APP   Component = "app"
	SAML  Component = "saml"
	OAuth Component = "oauth"
)

var ReconcileAnnotation = map[Component]string{
	APP:   "wso2.it.auth.gr/reconcile",
	SAML:  "wso2.it.auth.gr/reconcile-saml",
	OAuth: "wso2.it.auth.gr/reconcile-oauth",
}

func skipReconcile(c Component, sp *wso2v1alpha1.WSO2SP) bool {
	if sp.Annotations == nil {
		return false
	}
	return sp.Annotations[ReconcileAnnotation[c]] == "false"
}

func (r *WSO2SPReconciler) buildClient(ctx context.Context, sp *wso2v1alpha1.WSO2SP) (*wso2.Client, error) {
	instance := &wso2v1alpha1.WSO2ISInstance{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      sp.Spec.InstanceRef.Name,
		Namespace: sp.Namespace,
	}, instance); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("WSO2ISInstance %q not found", sp.Spec.InstanceRef.Name)
		}
		return nil, err
	}
	if instance.Status.Phase != "Ready" {
		return nil, fmt.Errorf("WSO2ISInstance %q is not ready: %s", sp.Spec.InstanceRef.Name, instance.Status.Message)
	}

	secretNS := instance.Spec.CredentialsSecret.Namespace
	if secretNS == "" {
		secretNS = instance.Namespace
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: secretNS, Name: instance.Spec.CredentialsSecret.Name}, secret); err != nil {
		return nil, fmt.Errorf("credentials secret: %w", err)
	}

	tenant := instance.Spec.TenantDomain
	if tenant == "" {
		tenant = "carbon.super"
	}

	return wso2.NewClient(
		instance.Spec.BaseURL,
		string(secret.Data["username"]),
		string(secret.Data["password"]),
		tenant,
		instance.Spec.InsecureSkipTLSVerify,
	), nil
}

func mapClaims(in []wso2v1alpha1.Claim) []wso2.Claim {
	if len(in) == 0 {
		return nil
	}
	out := make([]wso2.Claim, 0, len(in))
	for _, c := range in {
		out = append(out, wso2.Claim{
			URI:       c.URI,
			Mandatory: c.Mandatory,
		})
	}
	return out
}

func filterTokenBindings(in string) string {
	if in == "session" || in == "cookie" {
		return in
	}
	return ""
}

func filterScopeValidators(in []string) (out []string) {
	if len(in) == 0 {
		return nil
	}

	for _, c := range in {
		if c == "xacml" || c == "role" {
			out = append(out, c)
		}
	}
	return
}

func oauth2FromSpec(sp *wso2v1alpha1.WSO2SP) *wso2.OAuth2Config {
	return &wso2.OAuth2Config{
		CallbackURL:        sp.Spec.OAuth2.CallbackURL,
		GrantTypes:         sp.Spec.OAuth2.GrantTypes,
		PKCEMandatory:      sp.Spec.OAuth2.PKCEMandatory,
		PKCEPlain:          sp.Spec.OAuth2.PKCEPlain,
		PublicClient:       sp.Spec.OAuth2.PublicClient,
		TokenBinding:       filterTokenBindings(sp.Spec.OAuth2.TokenBinding),
		Audiences:          sp.Spec.OAuth2.Audiences,
		ScopeValidators:    filterScopeValidators(sp.Spec.OAuth2.ScopeValidators),
		RefreshTokenExpiry: sp.Spec.OAuth2.RefreshTokenExpiry,
		AccessTokenExpiry:  sp.Spec.OAuth2.AccessTokenExpiry,
	}
}

func authenticationStepsFromSpec(sp *wso2v1alpha1.WSO2SP) (steps []wso2.AuthenticationStep) {
	for _, c := range sp.Spec.AuthenticationSteps {
		steps = append(steps, wso2.AuthenticationStep{
			Step:                   c.Step,
			LocalAuthenticators:    c.LocalAuthenticators,
			FederatedIDP:           c.FederatedIDP,
			FederatedAuthenticator: c.FederatedAuthenticator,
		})
	}
	return
}
func applicationFromSpec(sp *wso2v1alpha1.WSO2SP) wso2.Application {
	return wso2.Application{
		ID:                  sp.Status.ID,
		ResourceID:          sp.Status.ResourceID,
		Name:                sp.Spec.Name,
		Description:         sp.Spec.Description,
		Claims:              mapClaims(sp.Spec.Claims),
		SubjectClaimURI:     sp.Spec.SubjectClaimURI,
		AuthenticationSteps: authenticationStepsFromSpec(sp),

		AlwaysSendBackAuthenticatedListOfIDPs: sp.Spec.AlwaysSendBackAuthenticatedListOfIDPs,
		EnableAuthorization:                   sp.Spec.EnableAuthorization,
		SkipConsent:                           sp.Spec.SkipConsent,
		SkipLogoutConsent:                     sp.Spec.SkipLogoutConsent,
		UseTenantInSub:                        sp.Spec.UseTenantInSub,
		UseUserstoreInSub:                     sp.Spec.UseUserstoreInSub,
		UseUserstoreInRoles:                   sp.Spec.UseUserstoreInRoles,

		StepForSubject:    sp.Spec.StepForSubject,
		StepForAttributes: sp.Spec.StepForAttributes,
		OAuth2: &wso2.OAuth2Config{
			Enabled: sp.Spec.OAuth2 != nil,
		},
		SAML: &wso2.SAMLConfig{
			Enabled: sp.Spec.SAML != nil,
		},
	}
}

func hash(a any) string {
	b, _ := json.Marshal(a)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeApplication(a *wso2.Application) *wso2.Application {
	an := *a
	an.ID = 0
	an.ResourceID = ""

	if an.Claims == nil {
		an.Claims = []wso2.Claim{}
	}

	// sort claims so order doesn't matter
	sort.Slice(a.Claims, func(i, j int) bool {
		return an.Claims[i].URI < a.Claims[j].URI
	})

	// normalize empty strings
	if an.Description == "" {
		an.Description = ""
	}
	return &an
}

func oauth2HasChanged(existing, desired *wso2.OAuth2Config) bool {
	// fmt.Println("Existin::OAUTH::", existing)
	// fmt.Println("Desired::OAUTH::", desired)
	eHash := hash(existing)
	dHash := hash(desired)
	// return existing.Description != desired.Description
	return eHash != dHash
}

func samlSPHasChanged(existing, desired *wso2.SAMLConfig) bool {
	// fmt.Println("Existin::SAML::", existing)
	// fmt.Println("Desired::SAML::", desired)
	eHash := hash(map[string]any{
		"issuer":   existing.Issuer,
		"acsurls":  existing.ACSURLs,
		"attr":     existing.EnableAttributeProfile,
		"attr_def": existing.EnableAttributesByDefault,
	})
	dHash := hash(map[string]any{
		"issuer":   desired.Issuer,
		"acsurls":  desired.ACSURLs,
		"attr":     desired.EnableAttributeProfile,
		"attr_def": desired.EnableAttributesByDefault,
	})
	// fmt.Println("Existin::SAML::hash::", eHash)
	// fmt.Println("Desired::SAML::hash::", dHash)
	return eHash != dHash
}

func appHasChanged(existing, desired *wso2.Application) bool {
	// fmt.Println("Desired::", desired)
	// fmt.Println("Existin::", existing)
	e := normalizeApplication(existing)
	d := normalizeApplication(desired)
	eHash := hash(e)
	dHash := hash(d)
	// return existing.Description != desired.Description
	return eHash != dHash
}

func (r *WSO2SPReconciler) setPhase(ctx context.Context, sp *wso2v1alpha1.WSO2SP, phase, msg string, requeue time.Duration) (ctrl.Result, error) {
	if sp.Status.Phase == phase &&
		sp.Status.Message == msg {
		return ctrl.Result{RequeueAfter: requeue}, nil
	}

	sp.Status.Phase = phase
	sp.Status.Message = msg

	if err := r.Status().Update(ctx, sp); err != nil {
		return ctrl.Result{}, nil
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}
