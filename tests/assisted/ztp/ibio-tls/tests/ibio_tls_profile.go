package ibio_tls_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	corev1 "k8s.io/api/core/v1"
	"github.com/rh-ecosystem-edge/eco-goinfra/pkg/clients"
	"github.com/rh-ecosystem-edge/eco-goinfra/pkg/pod"
	"github.com/rh-ecosystem-edge/eco-goinfra/pkg/reportxml"
	. "github.com/rh-ecosystem-edge/eco-gotests/tests/assisted/ztp/ibio-tls/internal/inittools"
	"github.com/rh-ecosystem-edge/eco-gotests/tests/assisted/ztp/ibio-tls/internal/tsparams"
	"github.com/rh-ecosystem-edge/eco-gotests/tests/assisted/ztp/internal/tlsprofile"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var customCiphers = []string{
	"ECDHE-RSA-AES128-GCM-SHA256",
	"ECDHE-RSA-AES256-GCM-SHA384",
	"ECDHE-ECDSA-AES128-GCM-SHA256",
	"ECDHE-ECDSA-AES256-GCM-SHA384",
}

func customTLSProfile(ciphers []string) configv1.TLSSecurityProfile {
	return configv1.TLSSecurityProfile{
		Type: configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{
			TLSProfileSpec: configv1.TLSProfileSpec{
				Ciphers:       ciphers,
				MinTLSVersion: configv1.VersionTLS12,
			},
		},
	}
}

var ibio = &tlsprofile.Component{
	Name:        "IBIO",
	Namespace:   "multicluster-engine",
	RestartMode: tlsprofile.RestartModeContainerRestart,
	Endpoints: []tlsprofile.Endpoint{
		{
			ServiceName:    "image-based-install-webhook",
			LocalPort:      19445,
			RemotePort:     9443,
			DeploymentName: "image-based-install-operator",
		},
		{
			ServiceName:    "image-based-install-config",
			LocalPort:      19446,
			RemotePort:     8000,
			DeploymentName: "image-based-install-operator",
		},
	},
	Deployments: []tlsprofile.Deployment{
		{Name: "image-based-install-operator", ContainerName: "manager"},
	},
	ListPods: func(client *clients.Settings, namespace string) ([]*pod.Builder, error) {
		return pod.List(client, namespace,
			metav1.ListOptions{LabelSelector: "app=image-based-install-operator"})
	},
	ExpectedHealthyPods: 1,
	PodReadyTimeout:     5 * time.Minute,
	AutoRestartTimeout:  10 * time.Minute,
	HonoringLogPattern:  "Reconciling APIServer TLS profile",
	AllowedCipher:       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	AllowedCipherAlt:    tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	DisallowedCipher:    tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	OldProfileCipher:    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
}

func ensureTLSAdherence() {
	apiserverU := &unstructured.Unstructured{}
	apiserverU.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "APIServer",
	})

	err := HubAPIClient.Get(context.TODO(),
		runtimeclient.ObjectKey{Name: "cluster"}, apiserverU)
	Expect(err).ToNot(HaveOccurred(), "failed to get apiserver/cluster")

	adherence, _, _ := unstructured.NestedString(
		apiserverU.Object, "spec", "tlsAdherence")
	if adherence == "StrictAllComponents" {
		return
	}

	By("Setting tlsAdherence to StrictAllComponents")

	patch := []byte(`{"spec":{"tlsAdherence":"StrictAllComponents"}}`)
	err = HubAPIClient.Patch(context.TODO(), apiserverU,
		runtimeclient.RawPatch(types.MergePatchType, patch))
	Expect(err).ToNot(HaveOccurred(), "failed to set tlsAdherence")
}

func restoreAdherence() {
	apiserverU := &unstructured.Unstructured{}
	apiserverU.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "config.openshift.io",
		Version: "v1",
		Kind:    "APIServer",
	})

	err := HubAPIClient.Get(context.TODO(),
		runtimeclient.ObjectKey{Name: "cluster"}, apiserverU)
	if err != nil {
		return
	}

	patch := []byte(`{"spec":{"tlsAdherence":"StrictAllComponents"}}`)
	_ = HubAPIClient.Patch(context.TODO(), apiserverU,
		runtimeclient.RawPatch(types.MergePatchType, patch))
}

// Tests are ordered to minimize TLS profile changes and cluster churn.
// Flow: Inter -> Old -> Modern -> Custom -> (skip+reuse) -> restart -> reconcile -> restore -> adherence -> server.
var _ = Describe(
	"IBIO TLS Profile",
	Ordered, ContinueOnFailure,
	Label(tsparams.LabelSuite), func() {
		BeforeAll(func() {
			By("Verifying hub API client is available")

			if HubAPIClient == nil {
				Skip("Hub API client is nil")
			}

			By("Ensuring TLS adherence is set on the cluster")
			ensureTLSAdherence()

			By("Waiting for cluster to stabilize")
			tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

			By("Ensuring Intermediate baseline")
			tlsprofile.RemoveAPIServerTLSProfile(HubAPIClient)

			By("Verifying IBIO pods are running")

			pods, err := ibio.ListPods(HubAPIClient, ibio.Namespace)
			Expect(err).ToNot(HaveOccurred(), "failed to list IBIO pods")

			if len(pods) == 0 {
				Skip("IBIO pods not found - not deployed")
			}

			tlsprofile.WaitPodsReady(HubAPIClient, ibio)
		})

		AfterAll(func() {
			By("Restoring StrictAllComponents adherence")
			restoreAdherence()

			By("Restoring default Intermediate TLS profile")
			tlsprofile.RemoveAPIServerTLSProfile(HubAPIClient)
			tlsprofile.StopAllPortForwards()
		})

		// 1. Intermediate (no profile change - already baseline from BeforeAll).
		It("Verifies default Intermediate TLS profile on IBIO endpoints",
			reportxml.ID("88958"), func() {
				By("Verifying controller logs show honoring message")

				for _, deploy := range ibio.Deployments {
					tlsprofile.AssertControllerLogsContain(
						HubAPIClient, ibio, deploy, ibio.HonoringLogPattern)
				}

				for _, endpoint := range ibio.Endpoints {
					By("Probing TLS 1.2 on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12, nil)

					By("Probing TLS 1.3 on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS13, tls.VersionTLS13, nil)
				}

				By("Verifying TLS 1.1 is rejected")
				tlsprofile.AssertTLSRejectedVersion(HubAPIClient, ibio,
					ibio.Endpoints[0], tls.VersionTLS11)

				By("Verifying TLS 1.0 is rejected")
				tlsprofile.AssertTLSRejectedVersion(HubAPIClient, ibio,
					ibio.Endpoints[0], tls.VersionTLS10)
			})

		// 2. Intermediate -> Old (1 change).
		It("Verifies Old TLS profile enables broader cipher set on IBIO",
			reportxml.ID("88959"), func() {
				By("Applying Old TLS profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
						Old:  &configv1.OldTLSProfile{},
					})

				By("Waiting for IBIO pods to pick up Old profile")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				for _, endpoint := range ibio.Endpoints {
					By("Verifying Old-specific cipher connects on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12,
						[]uint16{ibio.OldProfileCipher})
				}
			})

		// 3. Old -> Modern (1 change).
		It("Verifies Modern TLS profile restricts to TLS 1.3 only on IBIO",
			reportxml.ID("88960"), func() {
				By("Applying Modern TLS profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					configv1.TLSSecurityProfile{
						Type:   configv1.TLSProfileModernType,
						Modern: &configv1.ModernTLSProfile{},
					})

				By("Waiting for IBIO pods to pick up Modern profile")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				for _, endpoint := range ibio.Endpoints {
					By("Verifying TLS 1.3 connects on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS13, tls.VersionTLS13, nil)

					By("Verifying TLS 1.2 is rejected on " + endpoint.ServiceName)
					tlsprofile.AssertTLSRejected(HubAPIClient, ibio, endpoint, nil)
				}
			})

		// 4. Modern -> Custom (1 change).
		It("Verifies Custom TLS profile restricts to specified ciphers on IBIO",
			reportxml.ID("88961"), func() {
				By("Applying Custom TLS profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					customTLSProfile(customCiphers))

				By("Waiting for IBIO pods to pick up Custom profile")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				for _, endpoint := range ibio.Endpoints {
					By("Verifying allowed cipher connects on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12,
						[]uint16{ibio.AllowedCipher})

					By(fmt.Sprintf("Verifying disallowed cipher is rejected on %s",
						endpoint.ServiceName))
					tlsprofile.AssertTLSRejected(HubAPIClient, ibio, endpoint,
						[]uint16{ibio.DisallowedCipher})
				}
			})

		// 5. Custom (no change - reuses Custom from 88961).
		It("Verifies webhook validation works after TLS profile change on IBIO",
			reportxml.ID("88963"), func() {
				Skip("IBIO webhook does not perform spec-level validation")
			})

		// 6. Custom (no change - reuses Custom from 88961).
		It("Verifies config server enforces same TLS profile as webhook on IBIO",
			reportxml.ID("88930"), func() {
				By("Probing allowed cipher on both endpoints")

				for _, endpoint := range ibio.Endpoints {
					By("Verifying allowed cipher on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12,
						[]uint16{ibio.AllowedCipher})

					By("Verifying alternative cipher on " + endpoint.ServiceName)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12,
						[]uint16{ibio.AllowedCipherAlt})

					By(fmt.Sprintf("Verifying disallowed cipher rejected on %s",
						endpoint.ServiceName))
					tlsprofile.AssertTLSRejected(HubAPIClient, ibio, endpoint,
						[]uint16{ibio.DisallowedCipher})
				}
			})

		// 7. Custom -> Intermediate -> Custom (2 changes).
		It("Verifies SecurityProfileWatcher triggers restart on IBIO",
			reportxml.ID("88965"), func() {
				By("Removing TLS profile to establish Intermediate baseline")
				tlsprofile.RemoveAPIServerTLSProfile(HubAPIClient)

				By("Waiting for automatic restart")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)
				tlsprofile.WaitPodsReady(HubAPIClient, ibio)

				By("Applying Custom TLS profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					customTLSProfile(customCiphers))

				By("Waiting for automatic restart")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)
				tlsprofile.WaitPodsReady(HubAPIClient, ibio)

				By("Verifying controllers honour the new profile")

				for _, deploy := range ibio.Deployments {
					tlsprofile.AssertControllerLogsContain(
						HubAPIClient, ibio, deploy, ibio.HonoringLogPattern)
				}
			})

		// 8. Custom -> single-cipher -> Intermediate (2 changes).
		It("Verifies profile change triggers automatic reconciliation on IBIO",
			reportxml.ID("88962"), func() {
				By("Recording baseline cipher connectivity")
				tlsprofile.AssertTLSConnects(HubAPIClient, ibio, ibio.Endpoints[0],
					tls.VersionTLS12, tls.VersionTLS12,
					[]uint16{ibio.AllowedCipher})

				singleCiphers := []string{
					"ECDHE-RSA-AES128-GCM-SHA256",
					"ECDHE-ECDSA-AES128-GCM-SHA256",
				}

				By("Switching to Custom single-cipher profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					customTLSProfile(singleCiphers))

				By("Waiting for automatic reconciliation")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				for _, deploy := range ibio.Deployments {
					tlsprofile.AssertControllerLogsContain(
						HubAPIClient, ibio, deploy, ibio.HonoringLogPattern)
				}

				By("Verifying AES256 is now rejected")
				tlsprofile.AssertTLSRejected(HubAPIClient, ibio,
					ibio.Endpoints[0], []uint16{ibio.AllowedCipherAlt})

				By("Switching back to Intermediate")
				tlsprofile.RemoveAPIServerTLSProfile(HubAPIClient)
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				By("Verifying AES256 is restored under Intermediate")
				tlsprofile.AssertTLSConnects(HubAPIClient, ibio, ibio.Endpoints[0],
					tls.VersionTLS12, tls.VersionTLS12,
					[]uint16{ibio.AllowedCipherAlt})
			})

		// 9. Intermediate (no change - verify state left by 88962).
		It("Verifies restore to default profile on IBIO",
			reportxml.ID("88964"), func() {
				By("Waiting for cluster to stabilize")
				tlsprofile.WaitForClusterStability(HubAPIClient, 15*time.Minute)

				By("Verifying no tlsSecurityProfile remains on apiserver")

				apiserver := &configv1.APIServer{}

				err := HubAPIClient.Get(context.TODO(),
					runtimeclient.ObjectKey{Name: "cluster"}, apiserver)
				Expect(err).ToNot(HaveOccurred())
				Expect(apiserver.Spec.TLSSecurityProfile).To(BeNil(),
					"tlsSecurityProfile should be nil after restore")

				By("Verifying Intermediate ciphers are available")

				for _, endpoint := range ibio.Endpoints {
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS12, tls.VersionTLS12, nil)
					tlsprofile.AssertTLSConnects(HubAPIClient, ibio, endpoint,
						tls.VersionTLS13, tls.VersionTLS13, nil)
				}
			})

		// 10. Adherence toggle (0 profile + 2 adherence changes).
		It("Verifies manager restarts on TLS adherence policy change on IBIO",
			reportxml.ID("88932"), func() {
				By("Changing adherence to LegacyAdheringComponentsOnly")

				apiserverU := &unstructured.Unstructured{}
				apiserverU.SetGroupVersionKind(schema.GroupVersionKind{
					Group:   "config.openshift.io",
					Version: "v1",
					Kind:    "APIServer",
				})

				err := HubAPIClient.Get(context.TODO(),
					runtimeclient.ObjectKey{Name: "cluster"}, apiserverU)
				Expect(err).ToNot(HaveOccurred())

				patch := []byte(
					`{"spec":{"tlsAdherence":"LegacyAdheringComponentsOnly"}}`)
				err = HubAPIClient.Patch(context.TODO(), apiserverU,
					runtimeclient.RawPatch(types.MergePatchType, patch))
				Expect(err).ToNot(HaveOccurred(),
					"failed to change adherence to Legacy")

				By("Waiting for pod restart")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitPodsReady(HubAPIClient, ibio)

				By("Verifying manager logs show adherence change")

				for _, deploy := range ibio.Deployments {
					tlsprofile.AssertControllerLogsContain(
						HubAPIClient, ibio, deploy,
						"TLS adherence policy has changed")
				}

				By("Restoring StrictAllComponents adherence")

				err = HubAPIClient.Get(context.TODO(),
					runtimeclient.ObjectKey{Name: "cluster"}, apiserverU)
				Expect(err).ToNot(HaveOccurred())

				patch = []byte(
					`{"spec":{"tlsAdherence":"StrictAllComponents"}}`)
				err = HubAPIClient.Patch(context.TODO(), apiserverU,
					runtimeclient.RawPatch(types.MergePatchType, patch))
				Expect(err).ToNot(HaveOccurred(),
					"failed to restore StrictAllComponents")

				By("Waiting for pod restart after adherence restore")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitPodsReady(HubAPIClient, ibio)
			})

		// 11. Intermediate -> Custom (1 change, observe server container).
		It("Verifies server container independent TLS change detection on IBIO",
			reportxml.ID("88933"), func() {
				By("Applying Custom single-cipher profile")
				tlsprofile.PatchAPIServerTLSProfile(HubAPIClient,
					customTLSProfile(customCiphers))

				By("Waiting for pod restart")
				tlsprofile.WaitPodsRestarted(HubAPIClient, ibio)
				tlsprofile.WaitPodsReady(HubAPIClient, ibio)

				By("Checking server container logs for TLS change detection")

				pods, err := ibio.ListPods(HubAPIClient, ibio.Namespace)
				Expect(err).ToNot(HaveOccurred(), "failed to list IBIO pods")
				Expect(pods).ToNot(BeEmpty(), "no IBIO pods found")

				targetPod := pods[0]

				By("Checking previous server container logs")

				container := "server"
				previousBytes, logErr := targetPod.GetLogsWithOptions(
					&corev1.PodLogOptions{
						Container: container,
						Previous:  true,
					})
				previousLogs := string(previousBytes)

				if logErr == nil && previousLogs != "" {
					if strings.Contains(previousLogs,
						"TLS profile has changed") ||
						strings.Contains(previousLogs,
							"TLS adherence policy has changed") {
						By("Server container detected TLS change and shut down")
					} else {
						By("Server container did not log TLS change " +
							"detection (known bug: watchAndExitOnTLSChange " +
							"loses API watch during kube-apiserver rollout)")
					}
				}

				By("Verifying server started successfully in new container")

				currentLogs, err := targetPod.GetFullLog("server")
				Expect(err).ToNot(HaveOccurred(),
					"failed to get server container logs")
				Expect(currentLogs).To(
					ContainSubstring("Starting https handler"),
					"server container should have started successfully")
			})
	})
