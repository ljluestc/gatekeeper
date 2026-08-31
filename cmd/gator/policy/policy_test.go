package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-policy-agent/gatekeeper/v3/pkg/gator/policy/catalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallCommand_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError string
	}{
		{
			name:        "no args or bundle",
			args:        []string{},
			expectError: "specify policy name(s) or use --bundle",
		},
		{
			name:        "scoped enforcement action rejected",
			args:        []string{"test-policy", "--enforcement-action=scoped"},
			expectError: "scoped",
		},
		{
			name:        "invalid enforcement action",
			args:        []string{"test-policy", "--enforcement-action=invalid"},
			expectError: "invalid enforcement action",
		},
		{
			name:        "invalid output format",
			args:        []string{"test-policy", "-o", "xml"},
			expectError: "invalid output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset package-level vars
			installBundles = nil
			installEnforcementAction = ""
			installDryRun = false
			installOutput = ""

			cmd := newInstallCommand()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestUninstallCommand_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError string
	}{
		{
			name:        "no args or bundle",
			args:        []string{},
			expectError: "specify policy name(s) or use --bundle",
		},
		{
			name:        "invalid output format",
			args:        []string{"test-policy", "-o", "xml"},
			expectError: "invalid output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uninstallBundles = nil
			uninstallDryRun = false
			uninstallOutput = ""

			cmd := newUninstallCommand()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestUpgradeCommand_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError string
	}{
		{
			name:        "no args or all or bundle",
			args:        []string{},
			expectError: "specify policy name(s), use --bundle, or use --all",
		},
		{
			name:        "invalid enforcement action",
			args:        []string{"--all", "--enforcement-action=invalid"},
			expectError: "invalid enforcement action",
		},
		{
			name:        "invalid output format",
			args:        []string{"--all", "-o", "xml"},
			expectError: "invalid output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upgradeAll = false
			upgradeBundles = nil
			upgradeEnforcementAction = ""
			upgradeDryRun = false
			upgradeOutput = ""

			cmd := newUpgradeCommand()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestUpdateCommand_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError string
	}{
		{
			name:        "invalid output format",
			args:        []string{"-o", "xml"},
			expectError: "invalid output format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateInsecure = false
			updateOutput = ""

			cmd := newUpdateCommand()
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

func TestSearchCommand_ValidationErrors(t *testing.T) {
	// search requires exactly 1 arg (cobra.ExactArgs(1))
	cmd := newSearchCommand()
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestGenerateCatalogCommand_InvalidPath(t *testing.T) {
	cmd := newGenerateCatalogCommand()
	cmd.SetArgs([]string{"--library-path=/nonexistent/path/to/library"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "library")
}

// writeTestLibrary creates a minimal gatekeeper-library layout with a single
// ConstraintTemplate and returns the library root path.
func writeTestLibrary(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	policyDir := filepath.Join(root, "library", "general", "testpolicy")
	require.NoError(t, os.MkdirAll(policyDir, 0o755))
	template := `apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8stestpolicy
  annotations:
    metadata.gatekeeper.sh/version: "1.0.0"
    description: "A test policy"
`
	require.NoError(t, os.WriteFile(filepath.Join(policyDir, "template.yaml"), []byte(template), 0o600))
	return root
}

// TestGenerateCatalogCommand_CatalogVersion verifies --catalog-version populates
// metadata.catalogVersion, that the schema apiVersion is implementation-owned,
// and that the deprecated metadata.version schema field is not emitted.
func TestGenerateCatalogCommand_CatalogVersion(t *testing.T) {
	root := writeTestLibrary(t)
	outPath := filepath.Join(t.TempDir(), "catalog.yaml")

	cmd := newGenerateCatalogCommand()
	cmd.SetArgs([]string{
		"--library-path=" + root,
		"--output=" + outPath,
		"--catalog-version=2026.08.29",
	})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	cat, err := catalog.ParseCatalog(data)
	require.NoError(t, err)

	assert.Equal(t, catalog.SchemaAPIVersion, cat.APIVersion)
	assert.Equal(t, "2026.08.29", cat.Metadata.CatalogVersion)
	assert.Empty(t, cat.Metadata.Version, "deprecated metadata.version must not be emitted")
	assert.Equal(t, "2026.08.29", cat.Metadata.CatalogVersionString())
}

// TestGenerateCatalogCommand_DeprecatedVersionAlias verifies the deprecated
// --version flag now feeds metadata.catalogVersion instead of overriding the
// schema version.
func TestGenerateCatalogCommand_DeprecatedVersionAlias(t *testing.T) {
	root := writeTestLibrary(t)
	outPath := filepath.Join(t.TempDir(), "catalog.yaml")

	cmd := newGenerateCatalogCommand()
	cmd.SetArgs([]string{
		"--library-path=" + root,
		"--output=" + outPath,
		"--version=legacy-1.2.3",
	})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	cat, err := catalog.ParseCatalog(data)
	require.NoError(t, err)

	// The value lands in the content version, and the schema version is
	// unaffected (still implementation-owned).
	assert.Equal(t, catalog.SchemaAPIVersion, cat.APIVersion)
	assert.Equal(t, "legacy-1.2.3", cat.Metadata.CatalogVersion)
}

// TestGenerateCatalogCommand_DefaultNoCatalogVersion verifies that, with no
// version flag, the generated catalog omits catalogVersion and still validates.
func TestGenerateCatalogCommand_DefaultNoCatalogVersion(t *testing.T) {
	root := writeTestLibrary(t)
	outPath := filepath.Join(t.TempDir(), "catalog.yaml")

	cmd := newGenerateCatalogCommand()
	cmd.SetArgs([]string{
		"--library-path=" + root,
		"--output=" + outPath,
	})
	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	cat, err := catalog.ParseCatalog(data)
	require.NoError(t, err)

	assert.Empty(t, cat.Metadata.CatalogVersion)
	assert.Empty(t, cat.Metadata.Version)
	require.NoError(t, catalog.ValidateCatalogSchema(cat))
}
