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
	"strings"
	"time"

	dchv1alpha1 "github.com/opendatahub-io/data-connect-hub/dc-controller/api/dataconnecthub/v1alpha1"
	"github.com/pelletier/go-toml/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// postRender mutates the freshly rendered manifests in place, injecting every
// value that depends on the DataConnectService instance or on the cluster and
// therefore cannot live in the static kustomize base. This is the single
// place where rendered resources are modified after kustomize build:
//
//   - per-instance resource renaming, flight-service -> <cr.Name>-flight
//     (renderFlightService)
//   - dynamic config.toml values (injectDynamicConfig):
//     [global-connection-types] tenant-id ......... cr.Namespace
//     [flight-service] address .................... <flight>.<ns>.svc
//     [auth] discovery_service_account ............ rest-service SA identity
//     [auth] token_review_audiences ................ CR / platform audiences
//     [connectors.<name>] .......................... spec.flightService.connectors
//   - OTLP trace env vars on the service containers (reconcileTraceEnv)
//   - kube-rbac-proxy --auth-token-audiences arg
//   - content-hash annotations that trigger rolling restarts
//
// Values known before rendering (images, replicas, env, volumes, gateway
// parentRefs) are injected earlier via params.env and kustomize patches —
// see buildServicePatches, buildGatewayPatches and mergeParamsEnv.
func (r *DataConnectServiceReconciler) postRender(
	ctx context.Context,
	resources []*unstructured.Unstructured,
	cr *dchv1alpha1.DataConnectService,
	platCfg *platformConfig,
) error {
	log := logf.FromContext(ctx)

	renderFlightService(resources, cr.Name)

	inputs := dynamicInputs{
		Namespace:  cr.Namespace,
		FlightName: flightServiceResourceName(cr.Name),
		Audiences:  r.resolveTokenReviewAudiences(cr, platCfg),
	}
	if cr.Spec.FlightService != nil {
		inputs.Connectors = cr.Spec.FlightService.Connectors
	}

	authUpdated, err := injectDynamicConfig(resources, inputs)
	if err != nil {
		return fmt.Errorf("injecting dynamic config.toml values: %w", err)
	}
	if len(inputs.Audiences) > 0 && !authUpdated {
		log.Info("tokenReviewAudiences specified but no config.toml with [auth] section found in rendered manifests")
	}

	if !reconcileTraceEnv(resources, cr.Spec.Trace, nameRestServiceContainer, nameFlightServiceContainer) {
		log.V(1).Info("trace reconciliation: no service container found in rendered manifests")
	}

	if len(inputs.Audiences) > 0 {
		setKubeRbacProxyAudiences(resources, inputs.Audiences)
	}

	if err := r.annotateDeploymentsWithContentHash(ctx, resources, cr.Namespace); err != nil {
		return fmt.Errorf("annotating deployments with content hash: %w", err)
	}
	return nil
}

// dynamicInputs carries the instance-dependent values injected into rendered
// ConfigMaps, derived from the CR and the platform config.
type dynamicInputs struct {
	// Namespace is the operand namespace (cr.Namespace).
	Namespace string
	// FlightName is the per-instance Flight service resource name.
	FlightName string
	// Audiences are the token review audiences from the CR or platform config.
	Audiences []string
	// Connectors are per-connector settings from the CR flight-service spec.
	Connectors []dchv1alpha1.ConnectorConfig
}

// dynamicConfig is a typed overlay for the dynamic subset of config.toml.
// Only the sections set to non-nil are written; every other key of the
// rendered config.toml is preserved as-is.
type dynamicConfig struct {
	Auth                  *dynamicAuth                  `toml:"auth,omitempty"`
	FlightService         *dynamicFlightService         `toml:"flight-service,omitempty"`
	GlobalConnectionTypes *dynamicGlobalConnectionTypes `toml:"global-connection-types,omitempty"`
	Connectors            map[string]dynamicConnector   `toml:"connectors,omitempty"`
}

type dynamicAuth struct {
	TokenReviewAudiences    []string `toml:"token_review_audiences,omitempty"`
	DiscoveryServiceAccount string   `toml:"discovery_service_account,omitempty"`
}

type dynamicFlightService struct {
	Address string `toml:"address"`
}

type dynamicGlobalConnectionTypes struct {
	TenantID string `toml:"tenant-id"`
}

type dynamicConnector struct {
	Enabled               bool   `toml:"enabled"`
	ConnectionTimeoutSecs *int64 `toml:"connection_timeout_secs,omitempty"`
	RequestTimeoutSecs    *int64 `toml:"request_timeout_secs,omitempty"`
	ReadTimeoutSecs       *int64 `toml:"read_timeout_secs,omitempty"`
}

// injectDynamicConfig applies the dynamic config.toml values to every
// rendered ConfigMap carrying a config.toml key. It reports whether any
// [auth] section received token review audiences.
func injectDynamicConfig(resources []*unstructured.Unstructured, inputs dynamicInputs) (bool, error) {
	// Values derived from other rendered resources: the Flight service FQDN
	// and the rest-service ServiceAccount identity.
	flightFQDN := ""
	restServiceAccount := ""
	for _, obj := range resources {
		switch {
		case obj.GetKind() == kindService && strings.HasSuffix(obj.GetName(), inputs.FlightName):
			flightFQDN = fmt.Sprintf("%s.%s.svc", obj.GetName(), inputs.Namespace)
		case obj.GetKind() == kindServiceAccount && strings.HasSuffix(obj.GetName(), nameRestService+"-sa"):
			restServiceAccount = obj.GetName()
		}
	}
	saIdentity := ""
	if restServiceAccount != "" {
		saIdentity = fmt.Sprintf("system:serviceaccount:%s:%s", inputs.Namespace, restServiceAccount)
	}

	authUpdated := false
	for _, obj := range resources {
		if obj.GetKind() != kindConfigMap {
			continue
		}
		config, data, err := parseConfigMapTOML(obj)
		if err != nil {
			return false, fmt.Errorf("ConfigMap %q: %w", obj.GetName(), err)
		}
		if config == nil {
			continue
		}

		overlay, updated, err := buildDynamicConfig(obj, config, inputs, flightFQDN, saIdentity)
		if err != nil {
			return false, fmt.Errorf("ConfigMap %q: %w", obj.GetName(), err)
		}
		authUpdated = authUpdated || updated
		if overlay == nil {
			continue
		}

		overlayMap, err := marshalOverlay(overlay)
		if err != nil {
			return false, fmt.Errorf("ConfigMap %q: %w", obj.GetName(), err)
		}
		mergeConfigOverlay(config, overlayMap)
		if err := setConfigMapTOML(obj, config, data); err != nil {
			return false, fmt.Errorf("ConfigMap %q: %w", obj.GetName(), err)
		}
	}
	return authUpdated, nil
}

// buildDynamicConfig decides which dynamic values apply to one ConfigMap,
// based on the parsed config.toml and the resource identity:
//
//   - tenant-id is only replaced when the rendered manifest still carries the
//     kustomize default ("opendatahub"); custom overlays keep their value
//   - flight-service address is only replaced when still at its base default
//   - discovery_service_account requires an [auth] section and a Flight
//     service ConfigMap (name contains the flight instance name)
//   - token_review_audiences applies to any ConfigMap with an [auth] section
//   - connector settings apply to the Flight service ConfigMap (label
//     app.kubernetes.io/name = flight instance name)
//
// It reports whether token review audiences were written.
func buildDynamicConfig(
	obj *unstructured.Unstructured,
	config map[string]any,
	inputs dynamicInputs,
	flightFQDN, saIdentity string,
) (*dynamicConfig, bool, error) {
	var d dynamicConfig
	updated := false

	if gct, ok := config["global-connection-types"].(map[string]any); ok && gct["tenant-id"] == "opendatahub" {
		d.GlobalConnectionTypes = &dynamicGlobalConnectionTypes{TenantID: inputs.Namespace}
	}

	if fs, ok := config["flight-service"].(map[string]any); ok && fs["address"] == nameFlightService && flightFQDN != "" {
		d.FlightService = &dynamicFlightService{Address: flightFQDN}
	}

	if _, hasAuth := config["auth"].(map[string]any); hasAuth {
		var dynAuth dynamicAuth
		if strings.Contains(obj.GetName(), inputs.FlightName) && saIdentity != "" {
			dynAuth.DiscoveryServiceAccount = saIdentity
		}
		if len(inputs.Audiences) > 0 {
			dynAuth.TokenReviewAudiences = inputs.Audiences
			updated = true
		}
		if dynAuth.DiscoveryServiceAccount != "" || dynAuth.TokenReviewAudiences != nil {
			d.Auth = &dynAuth
		}
	}

	if len(inputs.Connectors) > 0 && obj.GetLabels()[labelAppName] == inputs.FlightName {
		connectors := make(map[string]dynamicConnector, len(inputs.Connectors))
		for _, connector := range inputs.Connectors {
			if connector.Name == "" {
				continue
			}
			dc := dynamicConnector{Enabled: connector.Enabled != nil && *connector.Enabled}
			var err error
			if dc.ConnectionTimeoutSecs, err = wholeSeconds(connector.ConnectionTimeout, "connectionTimeout", connector.Name); err != nil {
				return nil, false, err
			}
			if dc.RequestTimeoutSecs, err = wholeSeconds(connector.RequestTimeout, "requestTimeout", connector.Name); err != nil {
				return nil, false, err
			}
			if dc.ReadTimeoutSecs, err = wholeSeconds(connector.ReadTimeout, "readTimeout", connector.Name); err != nil {
				return nil, false, err
			}
			connectors[connector.Name] = dc
		}
		d.Connectors = connectors
	}

	if d.Auth == nil && d.FlightService == nil && d.GlobalConnectionTypes == nil && d.Connectors == nil {
		return nil, updated, nil
	}
	return &d, updated, nil
}

// wholeSeconds converts an optional duration override into whole seconds.
// It rejects zero, negative, or fractional-second durations.
func wholeSeconds(d *metav1.Duration, field, connector string) (*int64, error) {
	if d == nil {
		return nil, nil
	}
	if d.Duration <= 0 || d.Duration%time.Second != 0 {
		return nil, fmt.Errorf("connector %s %s must be a positive whole number of seconds", connector, field)
	}
	secs := int64(d.Duration / time.Second)
	return &secs, nil
}

// marshalOverlay round-trips a typed overlay through TOML into the generic
// map form used for merging. The struct tags define the written keys, and
// omitempty keeps unset fields from clobbering rendered values.
func marshalOverlay(overlay *dynamicConfig) (map[string]any, error) {
	b, err := toml.Marshal(overlay)
	if err != nil {
		return nil, fmt.Errorf("marshaling dynamic config overlay: %w", err)
	}
	var m map[string]any
	if err := toml.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("unmarshaling dynamic config overlay: %w", err)
	}
	return m, nil
}

// mergeConfigOverlay deep-merges an overlay into a parsed config: tables are
// merged recursively, every other value (including arrays) is replaced.
func mergeConfigOverlay(dst, overlay map[string]any) {
	for k, v := range overlay {
		if table, ok := v.(map[string]any); ok {
			if existing, ok := dst[k].(map[string]any); ok {
				mergeConfigOverlay(existing, table)
				continue
			}
		}
		dst[k] = v
	}
}
