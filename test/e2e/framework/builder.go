package framework

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func BuildFixture(fixturePath string) (string, error) {
	absPath, err := filepath.Abs(fixturePath)
	if err != nil {
		return "", err
	}
	
	dir := filepath.Dir(absPath)
	binName := filepath.Base(dir) + ".bin"
	binPath := filepath.Join(os.TempDir(), binName)
	
	cmd := exec.Command("go", "build", "-gcflags=-N -l", "-o", binPath, absPath)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=1")
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build failed: %v, output: %s", err, string(output))
	}
	
	return binPath, nil
}
