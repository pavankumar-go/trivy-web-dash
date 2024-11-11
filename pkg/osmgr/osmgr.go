package osmgr

import (
	"os"
	"os/exec"
)

var (
	DefaultMgr = &osmgr{}
)

type File interface {
	Name() string
	Read([]byte) (int, error)
}

type Mgr interface {
	Environ() []string
	LookPath(string) (string, error)
	RunCmd(cmd *exec.Cmd) ([]byte, error)
	TempFile(dir, pattern string) (File, error)
	Remove(name string) error
}

type osmgr struct {
}

func (o *osmgr) Environ() []string {
	return os.Environ()
}

func (o *osmgr) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	return cmd.CombinedOutput()
}

func (o *osmgr) TempFile(dir, pattern string) (File, error) {
	return os.CreateTemp(dir, pattern)
}

func (o *osmgr) Remove(name string) error {
	return os.Remove(name)
}

func (o *osmgr) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}
