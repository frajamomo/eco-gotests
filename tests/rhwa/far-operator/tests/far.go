package tests

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/openshift-kni/eco-goinfra/pkg/deployment"
	"github.com/openshift-kni/eco-goinfra/pkg/pod"
	"github.com/openshift-kni/eco-goinfra/pkg/reportxml"

	"github.com/openshift-kni/eco-gotests/tests/rhwa/far-operator/internal/farparams"
	. "github.com/openshift-kni/eco-gotests/tests/rhwa/internal/rhwainittools"
	"github.com/openshift-kni/eco-gotests/tests/rhwa/internal/rhwaparams"

	"github.com/golang/glog"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe(
	"FAR Post Deployment tests",
	Ordered,
	ContinueOnFailure,
	Label(farparams.Label), func() {
		BeforeAll(func() {
			By("Get FAR deployment object")
			farDeployment, err := deployment.Pull(
				APIClient, farparams.OperatorDeploymentName, rhwaparams.RhwaOperatorNs)
			Expect(err).ToNot(HaveOccurred(), "Failed to get FAR deployment")

			By("Verify FAR deployment is Ready")
			Expect(farDeployment.IsReady(rhwaparams.DefaultTimeout)).To(BeTrue(), "FAR deployment is not Ready")
		})

		It("Verify Fence Agents Remediation Operator pod is running", reportxml.ID("66026"), func() {

			listOptions := metav1.ListOptions{
				LabelSelector: fmt.Sprintf("app.kubernetes.io/name=%s", farparams.OperatorControllerPodLabel),
			}
			_, err := pod.WaitForAllPodsInNamespaceRunning(
				APIClient,
				rhwaparams.RhwaOperatorNs,
				rhwaparams.DefaultTimeout,
				listOptions,
			)
			Expect(err).ToNot(HaveOccurred(), "Pod is not ready")
		})

		It("Verify Fence Agents Remediation Operator passes trivy scan without vulnerabilities", reportxml.ID("76877"), func() {

			By("Creating temp directory")
			dirname, err := os.MkdirTemp("", "case76877_*")
			os.Chmod(dirname, 0755)
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(dirname)

			By("Creating rapidast output folder")
			resultsDirname := fmt.Sprintf("%s/results", dirname)
			err = os.MkdirAll(resultsDirname, 0755)
			Expect(err).NotTo(HaveOccurred())
			defer os.RemoveAll(resultsDirname)

			defer func() {
				command := fmt.Sprintf("sudo chown $USER -R %s", resultsDirname)
				_, permErrResultsDir := exec.Command("bash", "-c", command).Output()
				Expect(permErrResultsDir).To(BeNil(), "Error occurred restoring of permission for results directory")
			}()
			command := fmt.Sprintf("podman unshare chown 1000 %s", resultsDirname)
			_, permErrResultsDir := exec.Command("bash", "-c", command).Output()
			Expect(permErrResultsDir).To(BeNil(), "Error occurred updating permission for results directory")

			By("Getting KUBECONFIG env variable for trivy")
			kubeconfigPath := os.Getenv("KUBECONFIG")
			Expect(kubeconfigPath).NotTo(BeNil())

			By("Creating rapidast configuration")
			err = prepareRapidastConfig(dirname)
			Expect(err).NotTo(HaveOccurred())

			By("Creating podman command")
			rapiDastCmd := fmt.Sprintf("podman run -it --rm -v %s:/home/rapidast/.kube/config:Z -v %s:/test:Z -v %s:/opt/rapidast/results:Z %s rapidast.py --config /test/%s",
				kubeconfigPath,
				dirname,
				resultsDirname,
				rhwaparams.RapidastImage,
				rhwaparams.RapidastTemplateFile,
			)
			By("Running podman command")
			rapiDastOutput, err := exec.Command("bash", "-c", rapiDastCmd).Output()
			Expect(err).NotTo(HaveOccurred(), "Error occured during execution of RapiDast test")
			glog.V(rhwaparams.RhwaLogLevel).Infof("RapiDast test execution output is %s\n", rapiDastOutput)

			By("Checking output of trivy scan")
			Expect(strings.Contains(string(rapiDastOutput), `"Severity": "HIGH"`)).NotTo(BeTrue(),
				"Trivy scan report contains High severity vulnerabilities")
		})
	})

func prepareRapidastConfig(destinationPath string) error {

	workingDir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred(), err)

	templateDir := filepath.Join(workingDir, rhwaparams.RapidastTemplateFolder)
	rapidastConfigFile := filepath.Join(templateDir, rhwaparams.RapidastTemplateFile)

	f, err := os.Open(rapidastConfigFile)
	Expect(err).NotTo((HaveOccurred()))
	defer f.Close()

	content, err := io.ReadAll(f)
	Expect(err).NotTo((HaveOccurred()))

	yamlData := make(map[string]interface{})
	err = yaml.Unmarshal(content, &yamlData)
	Expect(err).NotTo((HaveOccurred()))

	sc := yamlData["scanners"].(map[string]interface{})
	genericTrivy := sc["generic_trivy"].(map[string]interface{})
	genericTrivy["inline"] = fmt.Sprintf("trivy k8s --kubeconfig=/home/rapidast/.kube/config -n %s pod --severity=HIGH,CRITICAL --scanners=misconfig --report all --format json",
		rhwaparams.RhwaOperatorNs)

	modifiedYaml, err := yaml.Marshal(yamlData)
	Expect(err).NotTo((HaveOccurred()))

	filePath := filepath.Join(destinationPath, rhwaparams.RapidastTemplateFile)
	rapidastConfig, err := os.Create(filePath)
	Expect(err).NotTo((HaveOccurred()))
	defer rapidastConfig.Close()

	_, err = rapidastConfig.Write(modifiedYaml)
	Expect(err).NotTo((HaveOccurred()))

	err = rapidastConfig.Close()
	Expect(err).NotTo((HaveOccurred()))

	return nil
}
