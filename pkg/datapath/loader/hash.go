// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/datapath/config"
	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	endpoint "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/version"
)

// datapathHash represents a unique enumeration of the datapath configuration.
type datapathHash []byte

// hashDatapath returns a new datapath hash based on the specified datapath and
// the digest returned by hashProducer.
func hashDatapath(c linuxConfig.Writer, nodeCfg *config.Config, producer []byte) (datapathHash, error) {
	d := sha256.New()
	err := c.WriteNodeConfig(d, nodeCfg)
	if err != nil {
		return nil, err
	}
	_, _ = d.Write(producer)
	return datapathHash(d.Sum(nil)), nil
}

// hashProducer digests the compile inputs that the datapath configuration does
// not cover: the BPF sources in bpfDir, the compiler, its flags and the agent
// version.
func hashProducer(ctx context.Context, logger *slog.Logger, bpfDir string) ([]byte, error) {
	h := sha256.New()

	err := filepath.WalkDir(bpfDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		fmt.Fprintf(h, "%s\x00", path)
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(h, f)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("hashing BPF sources in %s: %w", bpfDir, err)
	}

	compilerVersion, err := exec.CommandContext(ctx, compiler, "--version").CombinedOutput(logger, false)
	if err != nil {
		return nil, fmt.Errorf("getting %s version: %w", compiler, err)
	}
	_, _ = h.Write(compilerVersion)

	fmt.Fprintf(h, "%q %q %q %q %s %s", testIncludes, StandardCFlags, epProg.Options,
		hostEpProg.Options, getBPFCPU(logger), version.Version)

	return h.Sum(nil), nil
}

func (d datapathHash) hashEndpoint(c linuxConfig.Writer, nodeCfg *config.Config, epCfg endpoint.Config) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteEndpointConfig(h, epCfg); err != nil {
		return "", err
	}

	// Include endpoint configuration in the hash, otherwise different runtime
	// configurations will hash to the same value and the update will be skipped.
	if epCfg.IsHost() {
		for _, cfg := range ciliumHostConfiguration(epCfg, nodeCfg) {
			if _, err := fmt.Fprintf(h, "%+v", cfg); err != nil {
				return "", fmt.Errorf("hashing host configuration: %w", err)
			}
		}
	} else {
		for _, cfg := range endpointConfiguration(epCfg, nodeCfg) {
			if _, err := fmt.Fprintf(h, "%+v", cfg); err != nil {
				return "", fmt.Errorf("hashing endpoint runtime configuration: %w", err)
			}
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) hashTemplate(c linuxConfig.Writer, epCfg endpoint.Config) (string, error) {
	h := sha256.New()
	_, _ = h.Write(d)
	if err := c.WriteTemplateConfig(h, epCfg); err != nil {
		return "", err
	}

	// Host and workload endpoints use different BPF source files, but share
	// the template cache. Keep their cache keys separate even when their
	// generated template configuration is otherwise identical.
	templateSource := endpointProg
	if epCfg.IsHost() {
		templateSource = hostEndpointProg
	}
	_, _ = h.Write([]byte("\x00" + templateSource))

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (d datapathHash) String() string {
	return hex.EncodeToString(d)
}
