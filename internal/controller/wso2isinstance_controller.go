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

// Package controller is used to manage the group CRDs lifecycle
package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	wso2v1alpha1 "github.com/lamprosfasoulas/wso2is-operator/api/v1alpha1"
	"github.com/lamprosfasoulas/wso2is-operator/internal/wso2"
	"k8s.io/client-go/tools/events"
)

// WSO2ISInstanceReconciler reconciles a WSO2ISInstance object
type WSO2ISInstanceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
}

// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2isinstances,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2isinstances/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=wso2.it.auth.gr,resources=wso2isinstances/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

func (r *WSO2ISInstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	instance := &wso2v1alpha1.WSO2ISInstance{}
	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	logger.Info("reconciling WSO2ISInstance", "name", instance.Name)

	secretNS := instance.Spec.CredentialsSecret.Namespace
	if secretNS == "" {
		secretNS = instance.Namespace
	}
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{
		Namespace: secretNS,
		Name:      instance.Spec.CredentialsSecret.Name,
	}, secret); err != nil {
		// SecretMissing
		r.Recorder.Eventf(instance, nil, corev1.EventTypeWarning, "SecretMissing", "Reconciling",
			"Cannot read credentials secret %q: %v", instance.Spec.CredentialsSecret.Name, err)
		return r.setPhase(ctx, instance, "Failed", fmt.Sprintf("cannot read secret %q: %v",
			instance.Spec.CredentialsSecret.Name, err), 2*time.Minute)
	}

	username := string(secret.Data["username"])
	password := string(secret.Data["password"])
	if username == "" || password == "" {
		// InvalidSecret  (was Event, not Eventf)
		r.Recorder.Eventf(instance, nil, corev1.EventTypeWarning, "InvalidSecret", "Reconciling",
			"Secret must contain 'username' and 'password' keys")
		return r.setPhase(ctx, instance, "Failed", "secret missing 'username' or 'password' keys", 2*time.Minute)
	}

	tenant := instance.Spec.TenantDomain
	if tenant == "" {
		tenant = "carbon.super"
	}

	wso2Client := wso2.NewClient(
		instance.Spec.BaseURL,
		username,
		password,
		tenant,
		instance.Spec.InsecureSkipTLSVerify,
	)
	if err := wso2Client.Ping(); err != nil {
		logger.Error(err, "ping failed")
		// PingFailed
		r.Recorder.Eventf(instance, nil, corev1.EventTypeWarning, "PingFailed", "Reconciling",
			"Connection failed: %v", err)

		return r.setPhase(ctx, instance, "Failed", err.Error(), 15*time.Second)
	}

	wasReady := instance.Status.Phase == "Ready"
	if err := r.setPhaseNoRequeue(ctx, instance, "Ready", fmt.Sprintf("Connected to %s", instance.Spec.BaseURL)); err != nil {
		return ctrl.Result{}, err
	}
	if !wasReady {
		r.Recorder.Eventf(instance, nil, corev1.EventTypeNormal, "Connected", "Reconciling",
			"Successfully connected to %s", instance.Spec.BaseURL)
	}

	return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
}

func (r *WSO2ISInstanceReconciler) setPhase(ctx context.Context, inst *wso2v1alpha1.WSO2ISInstance, phase, msg string, requeue time.Duration) (ctrl.Result, error) {
	if err := r.setPhaseNoRequeue(ctx, inst, phase, msg); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *WSO2ISInstanceReconciler) setPhaseNoRequeue(ctx context.Context, inst *wso2v1alpha1.WSO2ISInstance, phase, msg string) error {
	inst.Status.Phase = phase
	inst.Status.Message = msg
	condStatus := metav1.ConditionTrue
	if phase != "Ready" {
		condStatus = metav1.ConditionFalse
	}
	setCondition(&inst.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             condStatus,
		Reason:             phase,
		Message:            msg,
		ObservedGeneration: inst.Generation,
	})
	return r.Status().Update(ctx, inst)
}

// setCondition upserts a condition by Type into the slice.
func setCondition(conditions *[]metav1.Condition, new metav1.Condition) {
	new.LastTransitionTime = metav1.Now()
	for i, c := range *conditions {
		if c.Type == new.Type {
			if c.Status == new.Status {
				new.LastTransitionTime = c.LastTransitionTime
			}
			(*conditions)[i] = new
			return
		}
	}
	*conditions = append(*conditions, new)
}

// SetupWithManager sets up the controller with the Manager.
func (r *WSO2ISInstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&wso2v1alpha1.WSO2ISInstance{}).
		Named("wso2isinstance").
		Complete(r)
}
