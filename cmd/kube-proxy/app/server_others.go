// +build !windows

/*
Copyright 2014 The Kubernetes Authors.

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

// Package app does all of the work necessary to configure and run a
// Kubernetes app process.
package app

import (
	"errors"
	"fmt"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/tools/record"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/features"
	"k8s.io/kubernetes/pkg/proxy"
	proxyconfigapi "k8s.io/kubernetes/pkg/proxy/apis/kubeproxyconfig"
	proxyconfig "k8s.io/kubernetes/pkg/proxy/config"
	"k8s.io/kubernetes/pkg/proxy/iptables"
	"k8s.io/kubernetes/pkg/proxy/ipvs"
	"k8s.io/kubernetes/pkg/util/configz"
	utilnode "k8s.io/kubernetes/pkg/util/node"

	"github.com/golang/glog"
)

// NewProxyServer returns a new ProxyServer.
func NewProxyServer(o *Options) (*ProxyServer, error) {
	return newProxyServer(o.config, o.CleanupAndExit, o.CleanupIPVS, o.scheme, o.master)
}

func newProxyServer(
	config *proxyconfigapi.KubeProxyConfiguration,
	cleanupAndExit bool,
	cleanupIPVS bool,
	scheme *runtime.Scheme,
	master string) (*ProxyServer, error) {

	if config == nil {
		return nil, errors.New("config is required")
	}

	if c, err := configz.New(proxyconfigapi.GroupName); err == nil {
		c.Set(config)
	} else {
		return nil, fmt.Errorf("unable to register configz: %s", err)
	}

	client, eventClient, err := createClients(config.ClientConnection, master)
	if err != nil {
		return nil, err
	}

	// Create event recorder
	hostname := utilnode.GetHostname(config.HostnameOverride)
	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(scheme, v1.EventSource{Component: "kube-proxy", Host: hostname})

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	var proxier proxy.ProxyProvider
	var serviceEventHandler proxyconfig.ServiceHandler = &serviceHandler{}
	var endpointsEventHandler proxyconfig.EndpointsHandler = &endpointHandler{}

	return &ProxyServer{
		Client:                client,
		EventClient:           eventClient,
		Broadcaster:           eventBroadcaster,
		Recorder:              recorder,
		ProxyMode:             proxyMode,
		NodeRef:               nodeRef,
		MetricsBindAddress:    config.MetricsBindAddress,
		ResourceContainer:     config.ResourceContainer,
		ConfigSyncPeriod:      config.ConfigSyncPeriod.Duration,
		ServiceEventHandler:   serviceEventHandler,
		EndpointsEventHandler: endpointsEventHandler,
	}, nil
}

type serviceHandler struct {
}

func (s *serviceHandler) OnServiceAdd(service *api.Service) {

}

// OnServiceUpdate is called whenever modification of an existing
// service object is observed.
func (s *serviceHandler) OnServiceUpdate(oldService, service *api.Service) {

}

// OnServiceDelete is called whenever deletion of an existing service
// object is observed.
func (s *serviceHandler) OnServiceDelete(service *api.Service) {

}

// OnServiceSynced is called once all the initial even handlers were
// called and the state is fully propagated to local cache.
func (s *serviceHandler) OnServiceSynced() {

}

type endpointsHandler struct {
}

// OnEndpointsAdd is called whenever creation of new endpoints object
// is observed.
func (e *endpointsHandler) OnEndpointsAdd(endpoints *api.Endpoints) {

}

// OnEndpointsUpdate is called whenever modification of an existing
// endpoints object is observed.
func (e *endpointsHandler) OnEndpointsUpdate(oldEndpoints, endpoints *api.Endpoints) {

}

// OnEndpointsDelete is called whever deletion of an existing endpoints
// object is observed.
func (e *endpointsHandler) OnEndpointsDelete(endpoints *api.Endpoints) {

}

// OnEndpointsSynced is called once all the initial event handlers were
// called and the state is fully propagated to local cache.
func (e *endpointsHandler) OnEndpointsSynced() {

}

func getProxyMode(proxyMode string, iptver iptables.IPTablesVersioner, khandle ipvs.KernelHandler, ipsetver ipvs.IPSetVersioner, kcompat iptables.KernelCompatTester) string {
	if proxyMode == proxyModeUserspace {
		return proxyModeUserspace
	}

	if len(proxyMode) > 0 && proxyMode == proxyModeIPTables {
		return tryIPTablesProxy(iptver, kcompat)
	}

	if utilfeature.DefaultFeatureGate.Enabled(features.SupportIPVSProxyMode) {
		if proxyMode == proxyModeIPVS {
			return tryIPVSProxy(iptver, khandle, ipsetver, kcompat)
		} else {
			glog.Warningf("Can't use ipvs proxier, trying iptables proxier")
			return tryIPTablesProxy(iptver, kcompat)
		}
	}
	glog.Warningf("Flag proxy-mode=%q unknown, assuming iptables proxy", proxyMode)
	return tryIPTablesProxy(iptver, kcompat)
}

func tryIPVSProxy(iptver iptables.IPTablesVersioner, khandle ipvs.KernelHandler, ipsetver ipvs.IPSetVersioner, kcompat iptables.KernelCompatTester) string {
	// guaranteed false on error, error only necessary for debugging
	// IPVS Proxier relies on ip_vs_* kernel modules and ipset
	useIPVSProxy, err := ipvs.CanUseIPVSProxier(khandle, ipsetver)
	if err != nil {
		// Try to fallback to iptables before falling back to userspace
		utilruntime.HandleError(fmt.Errorf("can't determine whether to use ipvs proxy, error: %v", err))
	}
	if useIPVSProxy {
		return proxyModeIPVS
	}

	// Try to fallback to iptables before falling back to userspace
	glog.V(1).Infof("Can't use ipvs proxier, trying iptables proxier")
	return tryIPTablesProxy(iptver, kcompat)
}

func tryIPTablesProxy(iptver iptables.IPTablesVersioner, kcompat iptables.KernelCompatTester) string {
	// guaranteed false on error, error only necessary for debugging
	useIPTablesProxy, err := iptables.CanUseIPTablesProxier(iptver, kcompat)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("can't determine whether to use iptables proxy, using userspace proxier: %v", err))
		return proxyModeUserspace
	}
	if useIPTablesProxy {
		return proxyModeIPTables
	}
	// Fallback.
	glog.V(1).Infof("Can't use iptables proxy, using userspace proxier")
	return proxyModeUserspace
}
