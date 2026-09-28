//go:build !unix

package policy

import (
	"errors"
	"os/exec"
)

func configureProcessGroup(*exec.Cmd) error {
	return errors.New("bundled Python policies require Unix process-group support")
}

func terminateProcessGroup(*exec.Cmd) error {
	return errors.New("bundled Python policies require Unix process-group support")
}
