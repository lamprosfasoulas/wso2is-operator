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

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	wso2v1alpha1 "github.com/lamprosfasoulas/wso2is-operator/api/v1alpha1"
	"github.com/lamprosfasoulas/wso2is-operator/internal/wso2"
)

const (
	spFinalizer  = "wso2.it.auth.gr/sp-finalizer"
	PhasePending = "Pending"
	PhaseFailed  = "Failed"
	PhaseReady   = "Ready"
	PhasePaused  = "Paused"
)

// WSO2SPReconciler reconciles a WSO2SP object
type WSO2SPReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// -- Core Logic --------------------------------------------------------------
func (r *WSO2SPReconciler) reconcileAdminAccess(ctx context.Context, sp *wso2v1alpha1.WSO2SP, wso2Client *wso2.Client) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if sp.Status.AdminCanView {
		return ctrl.Result{}, nil
	}
	canAdminView, groupID, err := wso2Client.GetAdminGroupMembership(sp.Spec.Name)
	if err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "GetFailed",
			"Failed to query WSO2 admin group membership: %v", err)
		return r.setPhase(ctx, sp, PhaseFailed,
			fmt.Sprintf("admin group lookup failed: %v", err),
			30*time.Second)
	}

	logger.Info("queried admin group membership",
		"application", sp.Spec.Name,
		"groupID", groupID,
		"canAdminView", canAdminView,
	)

	if canAdminView {
		sp.Status.AdminCanView = true
		return ctrl.Result{}, nil
	}

	logger.Info("granting admin group visibility", "groupID", groupID)
	if err := wso2Client.JoinAdminToGroup(groupID); err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "SetFailed",
			"Failed to update WSO2 admin group membership: %v", err)
		return r.setPhase(ctx, sp, PhaseFailed,
			fmt.Sprintf("admin group update failed: %v", err),
			30*time.Second)
	}

	// Membership was just granted; requeue shortly so AdminCanView gets
	// confirmed on the next iteration rather than assumed immediately.
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

func (r *WSO2SPReconciler) upsertApplicationSecret(ctx context.Context, sp *wso2v1alpha1.WSO2SP, kv map[string]string) error {
	for k, v := range kv {
		if k == "" || v == "" {
			delete(kv, k)
		}
	}
	if len(kv) == 0 {
		return nil
	}

	secretName := sp.Name + "-inbound"

	sec := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: sp.Namespace,
	}, sec)

	if apierrors.IsNotFound(err) {
		sec = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretName,
				Namespace: sp.Namespace,
			},
			StringData: kv,
		}
		if err := controllerutil.SetControllerReference(sp, sec, r.Scheme); err != nil {
			return err
		}
		return r.Create(ctx, sec)
	} else if err != nil {
		return err
	}
	if sec.StringData == nil {
		sec.StringData = map[string]string{}
	}
	for k, v := range kv {
		sec.StringData[k] = v
	}
	return r.Update(ctx, sec)
}

func (r *WSO2SPReconciler) populateInboundSecrets(ctx context.Context, sp *wso2v1alpha1.WSO2SP, desired *wso2.Application) error {
	if sp.Spec.OAuth2 == nil && sp.Spec.SAML == nil {
		return nil
	}

	fetchSecret := func(name string) (map[string][]byte, error) {
		sec := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: sp.Namespace}, sec); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, err
		}
		return sec.Data, nil
	}

	if sp.Spec.OAuth2 != nil {
		data, err := fetchSecret(sp.Name + "-inbound")
		if err != nil {
			return fmt.Errorf("oauth2 secret: %w", err)
		}
		if data != nil {
			desired.OAuth2 = &wso2.OAuth2Config{
				OAuthConsumerKey:    string(data["client_id"]),
				OAuthConsumerSecret: string(data["client_secret"]),
			}
		}
	}
	if sp.Spec.SAML != nil {
		data, err := fetchSecret(sp.Name + "-inbound")
		if err != nil {
			return fmt.Errorf("oauth2 secret: %w", err)
		}
		if data != nil {
			desired.SAML = &wso2.SAMLConfig{
				Issuer:                         string(data["saml_issuer"]),
				AttributeConsumingServiceIndex: string(data["saml_attrConsumingServiceIndex"]),
			}
		}
	}

	return nil
}

func (r *WSO2SPReconciler) reconcileApplicationOAuth2(ctx context.Context, sp *wso2v1alpha1.WSO2SP, wso2Client *wso2.Client) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	desired := oauth2FromSpec(sp)

	existing, err := wso2Client.GetApplicationOAuth2Config(sp.Status.ResourceID, sp.Spec.Name)
	if err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "GetOAuth2Failed", "Failed to query WSO2IS for OAuth2: %v", err)
		return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
	}
	// Create secret
	if existing == nil {
		logger.Info("creating oauth2 application")
		if err := wso2Client.CreateApplicationOAuth2Config(sp.Spec.Name, desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "CreateOAuth2Failed", "Failed to create app on WSO2IS: %v", err)
			return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
		}
		return ctrl.Result{
			RequeueAfter: 5 * time.Second,
		}, nil
	}

	if err := r.upsertApplicationSecret(ctx, sp, map[string]string{
		"client_id":     existing.OAuthConsumerKey,
		"client_secret": existing.OAuthConsumerSecret,
	}); err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "CreateOAuth2Failed", "Failed to create secret: %v", err)
		return ctrl.Result{}, err
	}

	desired.OAuthConsumerKey = existing.OAuthConsumerKey
	desired.OAuthConsumerSecret = existing.OAuthConsumerSecret
	if oauth2HasChanged(existing, desired) {
		logger.Info("updating oauth2 application")
		if err := wso2Client.UpdateApplicationOAuth2Config(sp.Spec.Name, desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "UpdateOAuth2Failed", "Failed to update app on WSO2IS: %v", err)
			return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
		}
		r.Recorder.Eventf(sp, corev1.EventTypeNormal, "OAuth2Updated",
			"OAuth2Application %q updated", sp.Spec.Name)
		return ctrl.Result{
			RequeueAfter: 5 * time.Second,
		}, nil
	}
	return ctrl.Result{}, nil
}

func (r *WSO2SPReconciler) reconcileSAMLApplication(ctx context.Context, sp *wso2v1alpha1.WSO2SP, wso2Client *wso2.Client) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	desired, err := wso2.Fetch(ctx, sp.Spec.SAML.MetadataURL)
	if err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "SAMLMetadataFailed",
			"Failed to fetch SAML metadata from %s: %v", sp.Spec.SAML.MetadataURL, err)
		return r.setPhase(ctx, sp, PhaseFailed,
			fmt.Sprintf("saml metadata fetch failed: %v", err), 30*time.Second)
	}

	desired.EnableAttributeProfile = sp.Spec.SAML.EnableAttributeProfile
	desired.EnableAttributesByDefault = sp.Spec.SAML.IncludeAttributesByDefault

	existing, err := wso2Client.GetApplicationSAMLConfig(desired.Issuer)
	if err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "GetSAMLFailed", "%v", err)
		return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
	}

	if existing.Issuer == "" {
		logger.Info("creating SAML SP", "issuer", desired.Issuer)
		if err := wso2Client.CreateSAMLApplication(desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "CreateSAMLFailed", "%v", err)
			return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
		}
		r.Recorder.Eventf(sp, corev1.EventTypeNormal, "SAMLCreated", "SAML SP %q created", desired.Issuer)
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Carry the index back so buildInboundAuthConfig can use it
	// desired.ACSURLs = existing.ACSURLs
	// sp.Status.SAML.Issuer = existing.Issuer

	if err := r.upsertApplicationSecret(ctx, sp, map[string]string{
		"saml_issuer":                    existing.Issuer,
		"saml_attrConsumingServiceIndex": existing.AttributeConsumingServiceIndex,
	}); err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "CreateSAMLFailed", "Failed to create secret: %v", err)
		return ctrl.Result{}, err
	}

	if samlSPHasChanged(existing, desired) {
		logger.Info("updating SAML SP", "issuer", desired.Issuer)
		if err := wso2Client.UpdateSAMLApplication(desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "UpdateSAMLFailed", "%v", err)
			return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
		}
		r.Recorder.Eventf(sp, corev1.EventTypeNormal, "SAMLUpdated", "SAML SP %q updated", desired.Issuer)
	}

	return ctrl.Result{}, nil
}

func (r *WSO2SPReconciler) reconcileApplication(ctx context.Context, sp *wso2v1alpha1.WSO2SP, wso2Client *wso2.Client) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if sp.Spec.OAuth2 != nil && !skipReconcile(OAuth, sp) {
		if res, err := r.reconcileApplicationOAuth2(ctx, sp, wso2Client); err != nil || !res.IsZero() {
			return res, err
		}
	}

	if sp.Spec.SAML != nil && sp.Spec.SAML.MetadataURL != "" && !skipReconcile(SAML, sp) {
		if res, err := r.reconcileSAMLApplication(ctx, sp, wso2Client); err != nil || !res.IsZero() {
			return res, err
		}
	}

	base := sp.DeepCopy()
	desired := applicationFromSpec(sp)

	existing, err := wso2Client.GetApplicationByName(sp.Spec.Name)
	if err != nil {
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "GetFailed", "Failed to query WSO2IS: %v", err)
		return r.setPhase(ctx, sp, PhaseFailed, err.Error(), 30*time.Second)
	}

	if existing == nil {
		logger.Info("creating application in WSO2IS", "name", sp.Spec.Name)
		if _, err := wso2Client.CreateApplication(desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "CreateFailed", "Failed to create application: %v", err)
			return r.setPhase(ctx, sp, PhaseFailed, fmt.Sprintf("create failed: %v", err), 30*time.Second)
		}
		r.Recorder.Eventf(sp, corev1.EventTypeNormal, "Created", sp.Spec.Name)

		sp.Status.Phase = PhasePending
		sp.Status.Message = "Application created, waiting for remote sync"

		if err := r.Status().Patch(ctx, sp, client.MergeFrom(base)); err != nil {
			return ctrl.Result{}, fmt.Errorf("patch status: %w", err)
		}

		return ctrl.Result{
			RequeueAfter: 5 * time.Second,
		}, nil
	}

	if sp.Status.ID != existing.ID || sp.Status.ResourceID != existing.ResourceID {
		logger.Info("updating status from remote application", "name", sp.Spec.Name)

		sp.Status.ID = existing.ID
		sp.Status.ResourceID = existing.ResourceID
	}

	if sp.Spec.AuthenticationScript != nil && sp.Spec.AuthenticationSteps != nil {
		cm := &corev1.ConfigMap{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      sp.Spec.AuthenticationScript.Name,
			Namespace: sp.Namespace,
		}, cm)

		if err != nil {
			return r.setPhase(ctx, sp, PhaseFailed, fmt.Sprintf("failed to get auth script configmap: %v", err), 30*time.Second)
		}
		desired.AuthenticationScript = cm.Data["script"]
	}

	// desired.SAML.Issuer = sp.Status.SAML.Issuer
	// desired.SAML.AttributeConsumingServiceIndex = sp.Status.SAML.AttributeConsumingServiceIndex
	if appHasChanged(existing, &desired) {
		// GET OAuth2 secret
		if err := r.populateInboundSecrets(ctx, sp, &desired); err != nil {
			return r.setPhase(ctx, sp, PhaseFailed, fmt.Sprintf("failed to read inbound secrets: %v", err), 30*time.Second)
		}

		logger.Info("updating application in WSO2IS", "name", sp.Spec.Name, "id", existing.ResourceID)
		if err := wso2Client.UpdateApplication(desired); err != nil {
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "UpdateFailed", "Failed to update application: %v", err)
			return r.setPhase(ctx, sp, PhaseFailed, fmt.Sprintf("update failed: %v", err), 30*time.Second)
		}
		r.Recorder.Eventf(sp, corev1.EventTypeNormal, "Updated",
			"Application %q updated", sp.Spec.Name)
	}

	sp.Status.Phase = PhaseReady
	sp.Status.Message = fmt.Sprintf("Application in sync (ID: %s)", existing.ResourceID)

	// Reconcile admin-group membership. On transient failure or requeue request
	// from this sub-step, return early without patching status — the next
	// reconcile iteration will re-evaluate from scratch.
	if res, err := r.reconcileAdminAccess(ctx, sp, wso2Client); err != nil || !res.IsZero() {
		return res, err
	}

	// All mutations are done; patch status in a single call.
	// sp.Status.ObservedGeneration = sp.Generation
	if err := r.Status().Patch(ctx, sp, client.MergeFrom(base)); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch status: %w", err)
	}

	// return ctrl.Result{RequeueAfter: 15 * time.Second}, nil
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

func (r *WSO2SPReconciler) handleDelete(ctx context.Context, sp *wso2v1alpha1.WSO2SP, wso2Client *wso2.Client) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	if sp.Status.ResourceID != "" {
		logger.Info("deleting application from WSO2IS",
			"name", sp.Spec.Name,
			"id", sp.Status.ID,
		)
		if err := wso2Client.DeleteApplication(sp.Spec.Name); err != nil {
			logger.Error(err, "failed to delete application from WSO2IS — may be orphaned",
				"id", sp.Status.ID,
			)
			r.Recorder.Eventf(sp, corev1.EventTypeWarning, "DeleteFailed",
				"Could not delete application from WSO2IS (may be orphaned): %v", err)
		} else {
			r.Recorder.Eventf(sp, corev1.EventTypeNormal, "Deleted",
				"Application %q deleted from WSO2IS", sp.Spec.Name)
		}
	}

	controllerutil.RemoveFinalizer(sp, spFinalizer)
	return ctrl.Result{}, r.Update(ctx, sp)
}

// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2sps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2sps/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2sps/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2isinstances,verbs=get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the WSO2SP object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.23.3/pkg/reconcile
func (r *WSO2SPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	sp := &wso2v1alpha1.WSO2SP{}
	if err := r.Get(ctx, req.NamespacedName, sp); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if skipReconcile(APP, sp) {
		if sp.Status.Phase != PhasePaused {
			sp.Status.Phase = PhasePaused
			if err := r.Status().Update(ctx, sp); err != nil {
				return ctrl.Result{}, err
			}
		}
		logger.Info("reconciliation paused", "name", sp.Name)
		return ctrl.Result{}, nil
	}

	wso2Client, err := r.buildClient(ctx, sp)
	if err != nil {
		logger.Info("instance not ready, requeueing", "reason", err.Error())
		r.Recorder.Eventf(sp, corev1.EventTypeWarning, "InstanceNotReady", "%v", err)
		return r.setPhase(ctx, sp, PhasePending, err.Error(), 15*time.Second)
	}

	if !sp.DeletionTimestamp.IsZero() {
		return r.handleDelete(ctx, sp, wso2Client)
	}
	if !controllerutil.ContainsFinalizer(sp, spFinalizer) {
		controllerutil.AddFinalizer(sp, spFinalizer)
		if err := r.Update(ctx, sp); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return r.reconcileApplication(ctx, sp, wso2Client)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WSO2SPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wso2v1alpha1.WSO2SP{}).
		Named("wso2sp").
		Complete(r)
}
