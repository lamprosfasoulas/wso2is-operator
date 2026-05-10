/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Claim struct {
	URI string `json:"uri"`
	// +optional
	Mandatory bool `json:"mandatory"`
}

type OAuth2Config struct {
	CallbackURL string   `json:"callbackURL"`
	GrantTypes  []string `json:"grantTypes"`
	// +optional
	// +kubebuilder:default:=true
	PKCEMandatory bool `json:"pkceMandatory,omitempty"`
	PKCEPlain     bool `json:"pkcePlain,omitempty"`
	PublicClient  bool `json:"publicClient,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=session;cookie
	TokenBinding string `json:"tokenBinding,omitempty"`
	// +optional
	Audiences []string `json:"audiences,omitempty"`
	// +optional
	ScopeValidators []string `json:"scopeValidators,omitempty"`
	// time in seconds
	// +kubebuilder:default:=3600
	RefreshTokenExpiry int `json:"refreshTokenExpiry,omitempty"`
	// time in seconds
	// +kubebuilder:default:=3600
	AccessTokenExpiry int `json:"accessTokenExpiry,omitempty"`
}
type SAMLConfig struct {
	MetadataURL                string `json:"metadataURL,omitempty"`
	EnableAttributeProfile     bool   `json:"enableAttributeProfile,omitempty"`
	IncludeAttributesByDefault bool   `json:"includeAttributesByDefault,omitempty"`
}

type AuthenticationStep struct {
	//+kubebuilder:validation:Required
	Step                   int      `json:"step"`
	LocalAuthenticators    []string `json:"localAuthenticators,omitempty"`
	FederatedIDP           string   `json:"federatedIDP,omitempty"`
	FederatedAuthenticator string   `json:"federatedAuthenticator,omitempty"`
}

// WSO2SPSpec defines the desired state of WSO2SP
type WSO2SPSpec struct {
	// Name of a WSO2ISInstance CR in the same namespace
	//+kubebuilder:validation:Required
	InstanceRef *corev1.LocalObjectReference `json:"instanceRef"`

	// The application name in WSO2IS
	//+kubebuilder:validation:Required
	Name string `json:"name"`

	// Claim Mappings for this SP
	// +optional
	Claims []Claim `json:"claims,omitempty"`

	// +optional
	Description string `json:"description,omitempty"`

	//+kubebuilder:validation:Required
	SubjectClaimURI string `json:"subjectURI"`

	// +optional
	SAML *SAMLConfig `json:"saml,omitempty"`

	// +optional
	OAuth2              *OAuth2Config        `json:"oauth2,omitempty"`
	AuthenticationSteps []AuthenticationStep `json:"authenticationSteps,omitempty"`
	// ConfigMap ref that defines Adaptive Authentication Script
	// +optional
	AuthenticationScript *corev1.LocalObjectReference `json:"authenticationScript,omitempty"`

	// +optional
	AlwaysSendBackAuthenticatedListOfIDPs bool `json:"alwaysSendBackAuthenticatedListOfIDPs,omitempty"`

	EnableAuthorization bool `json:"enableAuthorization,omitempty"`
	// +optional
	SkipConsent bool `json:"skipConsent,omitempty"`
	// +optional
	SkipLogoutConsent bool `json:"skipLogoutConsent,omitempty"`
	// Use Tenant domain in local subject identifier
	// +optional
	UseTenantInSub bool `json:"useTenantInSub,omitempty"`
	// Use User store domain in local subject identifier
	// +kubebuilder:default=true
	UseUserstoreInSub bool `json:"useUserstoreInSub,omitempty"`
	// +optional
	UseUserstoreInRoles bool `json:"useUserstoreInRoles,omitempty"`

	// +kubebuilder:default:=1
	StepForSubject int `json:"stepForSubject,omitempty"`
	// +kubebuilder:default:=1
	StepForAttributes int `json:"stepForAttr,omitempty"`
}

// WSO2SPStatus defines the observed state of WSO2SP.
type WSO2SPStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Internal WSO2IS application ID — stored so we can update/delete it
	// +optional
	ID int `json:"id,omitempty"`
	// +optional
	ResourceID string `json:"resourceID,omitempty"`
	// +optional
	// +kubebuilder:validation:Enum=Pending;Ready;Failed;Paused
	Phase string `json:"phase,omitempty"`
	// +optional
	AdminCanView bool `json:"adminCanView,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`

	// conditions represent the current state of the WSO2SP resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Instance",type=string,JSONPath=`.spec.instanceRef.name`
// +kubebuilder:printcolumn:name="Name",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="AdminCanView",type=string,JSONPath=`.status.adminCanView`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="ID",type=string,JSONPath=`.status.id`

type WSO2SP struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of WSO2SP
	// +required
	Spec WSO2SPSpec `json:"spec"`

	// status defines the observed state of WSO2SP
	// +optional
	Status WSO2SPStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// WSO2SPList contains a list of WSO2SP
type WSO2SPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []WSO2SP `json:"items"`
}

func init() {
	SchemeBuilder.Register(&WSO2SP{}, &WSO2SPList{})
}
