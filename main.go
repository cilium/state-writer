// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/addressing"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath"
	datapathConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	labelsModel "github.com/cilium/cilium/pkg/labels/model"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/version"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const prefix = "/var/run/cilium/state"

type fakeOwner struct{}

var fakeOwnerInstance = &fakeOwner{}

func (f *fakeOwner) GetPolicyRepository() *policy.Repository {
	return &policy.Repository{}
}

func (f *fakeOwner) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

func (f *fakeOwner) GetCompilationLock() *lock.RWMutex {
	return nil
}

func (f *fakeOwner) SendNotification(typ monitorAPI.AgentNotification, text string) error {
	return nil
}

func (f *fakeOwner) Datapath() datapath.Datapath {
	return nil
}

var (
	log            = logrus.New()
	shutdownSignal = make(chan struct{})
)

func writeState(ep *models.Endpoint) error {
	if ep.Status == nil {
		return fmt.Errorf("no .Status field")
	}

	// The NotReady state is only known to the API
	if ep.Status.State == models.EndpointStateNotReady {
		ep.Status.State = models.EndpointStateReady
	}

	// Lost information:
	//DatapathMapID int
	//DNSZombies *fqdn.DNSZombieMappings
	//DatapathConfiguration models.EndpointDatapathConfiguration
	e := endpoint.SerializableEndpoint{ID: uint16(ep.ID)}

	e.Options = option.NewIntOptions(&endpoint.EndpointMutableOptionLibrary)
	e.Options.Library = &endpoint.EndpointMutableOptionLibrary
	e.Options.Opts = option.OptionMap{}

	if ep.Status.ExternalIdentifiers != nil {
		if ep.Status.ExternalIdentifiers.PodName != "" {
			parts := strings.SplitN(ep.Status.ExternalIdentifiers.PodName, "/", 2)
			if len(parts) == 2 {
				e.K8sPodName = parts[0]
				e.K8sNamespace = parts[1]
			} else {
				log.Warningf("Invalid namespac/pod name '%s' for endpoint %d",
					ep.Status.ExternalIdentifiers.PodName, e.ID)
			}
		} else {
			e.K8sPodName = ep.Status.ExternalIdentifiers.K8sPodName
			e.K8sNamespace = ep.Status.ExternalIdentifiers.K8sNamespace
		}

		e.ContainerName = ep.Status.ExternalIdentifiers.ContainerName
		e.ContainerID = ep.Status.ExternalIdentifiers.ContainerID
		e.DockerNetworkID = ep.Status.ExternalIdentifiers.DockerNetworkID
		e.DockerEndpointID = ep.Status.ExternalIdentifiers.DockerEndpointID
	} else {
		log.Warningf("Endpoint %d is missing ExternalIdentifiers", ep.ID)
	}

	if ep.Status.Identity != nil {
		e.SecurityIdentity = &identity.Identity{
			ID:           identity.NumericIdentity(ep.Status.Identity.ID),
			Labels:       labels.NewLabelsFromModel(ep.Status.Identity.Labels),
			LabelsSHA256: ep.Status.Identity.LabelsSHA256,
		}
	} else {
		log.Warningf("Endpoint %d is missing identity information", ep.ID)
	}

	if networking := ep.Status.Networking; networking != nil {
		if len(networking.Addressing) > 0 {
			if networking.Addressing[0].IPV4 != "" {
				ipv4, err := addressing.NewCiliumIPv4(networking.Addressing[0].IPV4)
				if err != nil {
					log.WithError(err).Warningf("Unable to parse IPv4 address of endpoint %d", ep.ID)
				}
				e.IPv4 = ipv4
			}

			if networking.Addressing[0].IPV6 != "" {
				ipv6, err := addressing.NewCiliumIPv6(networking.Addressing[0].IPV6)
				if err != nil {
					log.WithError(err).Warningf("Unable to parse IPv6 address of endpoint %d", ep.ID)
				}
				e.IPv6 = ipv6
			}
		} else {
			log.Warningf("Endpoint %d is missing addressing information", ep.ID)
		}

		if networking.HostMac != "" {
			m, err := mac.ParseMAC(networking.HostMac)
			if err != nil {
				log.WithError(err).Warningf("Unable to parse node MAC '%s' of endpoint %d", networking.HostMac, e.ID)
			} else {
				e.NodeMAC = m
			}
		} else {
			log.Warningf("Endpoint %d is missing node MAC information", ep.ID)
		}

		e.IfIndex = int(networking.InterfaceIndex)
		e.IfName = networking.InterfaceName

		if networking.Mac != "" {
			m, err := mac.ParseMAC(networking.Mac)
			if err != nil {
				log.WithError(err).Warningf("Unable to parse MAC '%s' of endpoint %d", networking.Mac, e.ID)
			} else {
				e.LXCMAC = m
			}
		} else {
			log.Warningf("Endpoint %d is missing endpoint MAC information", ep.ID)
		}
	} else {
		log.Warningf("Endpoint %d is missing networking information", ep.ID)
	}

	if ep.Status.Labels != nil {
		e.OpLabels = *labelsModel.NewOplabelsFromModel(ep.Status.Labels)
	} else {
		log.Warningf("Endpoint %d is missing label information", ep.ID)
	}

	if ep.Status.Realized != nil {
		om, err := endpoint.EndpointMutableOptionLibrary.ValidateConfigurationMap(ep.Status.Realized.Options)
		if err != nil {
			log.WithError(err).Warning("Invalid endpoint options observed")
		} else {
			noop := func(key string, value option.OptionSetting, data interface{}) {}
			e.Options.ApplyValidated(om, noop, nil)
		}
	} else {
		log.Warningf("Endpoint %d is missing endpoint configuration information", ep.ID)
	}

	e2 := endpoint.NewEndpointWithState(fakeOwnerInstance, nil, nil, e.ID, string(ep.Status.State))
	e2.FromSerializedEndpoint(&e)

	headerPath := filepath.Join(prefix, strconv.Itoa(int(ep.ID)), common.CHeaderFileName)

	_, err := os.Stat(headerPath)
	if !os.IsNotExist(err) && os.Getenv("OVERWRITE_HEADERFILE") == "" {
		log.WithField("file", headerPath).Info("Skipping already existing headerfile")
		return nil
	}

	f, err := os.Create(headerPath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for writing: %s", headerPath, err)

	}
	defer f.Close()

	if err = e2.WriteInformationalComments(f); err != nil {
		return err
	}

	writer := &datapathConfig.HeaderfileWriter{}
	if err := writer.WriteEndpointConfig(f, e2); err != nil {
		return err
	}

	log.Infof("Wrote %s endpoint %d", headerPath, ep.ID)
	return nil
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGINT, unix.SIGTERM)

	go func() {
		<-signals
		close(shutdownSignal)
	}()

	if ver := os.Getenv("CILIUM_VERSION"); ver != "" {
		version.Version = ver
	} else {
		version.Version = "0.0.0 0000000 2020-05-13T22:55:12-08:00 go version go1.12.5 linux/amd64"
	}

	c, err := client.NewClient("")
	if err != nil {
		log.WithError(err).Fatal("Cannot create Cilium client")
	}

	for {

		endpoints, err := c.EndpointList()
		if err != nil {
			log.WithError(err).Fatalf("Cannot list Cilium endpoints")
		}

		for _, ep := range endpoints {
			log.Infof("Processing endpoint %d", ep.ID)

			if err := writeState(ep); err != nil {
				log.WithError(err).Warning("Unable to write state of endpoint %#v", ep)
			}
		}

		select {
		case <-shutdownSignal:
			return
		case <-time.After(5 * time.Minute):
		}
	}
}
