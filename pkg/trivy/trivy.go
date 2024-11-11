package tyivy

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/trivy-web-dash/pkg/logger"
	"github.com/trivy-web-dash/pkg/osmgr"
	"github.com/trivy-web-dash/types"
	"golang.org/x/xerrors"
)

const trivyoutput = "json"
const trivyCmd = "trivy"

type TC struct {
	Server string
	logger logger.Logger
	mgr    osmgr.Mgr
}

func NewTrivyClient(l logger.Logger, s string) *TC {
	return &TC{
		Server: s,
		logger: l,
		mgr:    osmgr.DefaultMgr,
	}
}

func (t *TC) Scan(imageRef string) (report *types.Report, err error) {
	reportFile, err := t.mgr.TempFile("/tmp/", "scan_report_*.json")
	if err != nil {
		t.logger.Debugf("error creating report tmp file : %v", err)
		return nil, err
	}

	t.logger.Debugf("saving scan to tmp file path : %s", reportFile.Name())
	defer func() {
		t.logger.Debugf("removing scan report tmp file path : %s", reportFile.Name())
		err = t.mgr.Remove(reportFile.Name())
		if err != nil {
			t.logger.Errorf("unable to remove scan tmp file : %s", err.Error())
		}
	}()

	cmd, err := t.prepareScanCmd(imageRef, reportFile.Name())
	if err != nil {
		t.logger.Errorf("failed to prepare scan command : %v", err)
		return nil, err
	}

	t.logger.Debugf("executing command path: %s args: %+q", cmd.Path, cmd.Args)

	stdout, err := t.mgr.RunCmd(cmd)
	if err != nil {
		t.logger.Errorf("trivy run failed image_ref : %s exit_code : %d stdout : %s", imageRef, cmd.ProcessState.ExitCode(), string(stdout))
		return nil, xerrors.Errorf("running trivy: %v: %v", err, string(stdout))
	}

	t.logger.Debugf("trivy run finished image_ref : %s exit_code : %d stdout : %s", imageRef, cmd.ProcessState.ExitCode(), string(stdout))

	var r types.Report
	err = json.NewDecoder(reportFile).Decode(&r)
	if err != nil {
		t.logger.Errorf("error decode scan report : %v", err)
		return nil, fmt.Errorf("decoding scan report from file: %w", err)
	}

	return &r, err
}

func (t *TC) prepareScanCmd(imageRef string, outputFile string) (*exec.Cmd, error) {
	args := []string{
		"image",
		"--server", t.Server,
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--ignore-unfixed",
		"--format", trivyoutput,
		"--output", outputFile,
		imageRef,
	}

	name, err := t.mgr.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)

	cmd.Env = t.mgr.Environ()
	return cmd, nil
}

func (t *TC) GetVersion() (*types.VersionInfo, error) {
	cmd, err := t.prepareVersionCmd()
	if err != nil {
		return nil, err
	}

	versionOutput, err := t.mgr.RunCmd(cmd)
	if err != nil {
		t.logger.Error("running trivy failed")
		return nil, fmt.Errorf("running trivy: %v: %v", err, string(versionOutput))
	}

	var vi types.VersionInfo
	if err := json.Unmarshal(versionOutput, &vi); err != nil {
		return nil, err
	}

	return &vi, nil
}

func (t *TC) prepareVersionCmd() (*exec.Cmd, error) {
	args := []string{
		"--version",
		"--cache-dir", "/tmp/",
		"--format", "json",
	}

	name, err := t.mgr.LookPath(trivyCmd)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(name, args...)
	return cmd, nil
}
