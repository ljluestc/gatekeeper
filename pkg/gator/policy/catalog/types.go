package catalog

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind is the required value of a catalog's kind field.
const Kind = "PolicyCatalog"

// SchemaAPIVersion is the catalog schema/API version emitted by this build's
// generator. It is the sole schema discriminator for a catalog and is owned by
// the implementation: catalog producers cannot override it. Increment (introduce
// a new group version) whenever fields are added or removed from the schema.
const SchemaAPIVersion = "gator.gatekeeper.sh/v1alpha1"

// supportedAPIVersions is the set of catalog schema/API versions this build can
// load. A catalog declaring an apiVersion outside this set is rejected so that
// clients never silently ignore fields from a newer, unknown schema.
var supportedAPIVersions = map[string]struct{}{
	SchemaAPIVersion: {},
}

// IsSupportedAPIVersion reports whether the given catalog apiVersion is a schema
// version this build understands.
func IsSupportedAPIVersion(apiVersion string) bool {
	_, ok := supportedAPIVersions[apiVersion]
	return ok
}

// SupportedAPIVersions returns the sorted list of catalog schema/API versions
// this build can load. Used to build actionable error messages.
func SupportedAPIVersions() []string {
	versions := make([]string, 0, len(supportedAPIVersions))
	for v := range supportedAPIVersions {
		versions = append(versions, v)
	}
	sort.Strings(versions)
	return versions
}

// PolicyCatalog represents the root catalog structure for policy discovery.
type PolicyCatalog struct {
	APIVersion string          `json:"apiVersion" yaml:"apiVersion"`
	Kind       string          `json:"kind" yaml:"kind"`
	Metadata   CatalogMetadata `json:"metadata" yaml:"metadata"`
	Bundles    []Bundle        `json:"bundles" yaml:"bundles"`
	Policies   []Policy        `json:"policies" yaml:"policies"`

	// Cached indexes for O(1) lookups (built lazily, thread-safe)
	policyIndex     map[string]int `json:"-" yaml:"-"`
	bundleIndex     map[string]int `json:"-" yaml:"-"`
	policyIndexOnce sync.Once      `json:"-" yaml:"-"`
	bundleIndexOnce sync.Once      `json:"-" yaml:"-"`
}

// CatalogMetadata contains metadata about the catalog itself.
type CatalogMetadata struct {
	// Name is the catalog identifier.
	Name string `json:"name" yaml:"name"`
	// CatalogVersion is the producer-owned version of this catalog's *contents*
	// (which policies/bundles it publishes). It is distinct from the schema
	// version (apiVersion) and is free-form: public and private catalog
	// producers may version their catalogs however they like.
	CatalogVersion string `json:"catalogVersion,omitempty" yaml:"catalogVersion,omitempty"`
	// Version is the deprecated catalog-version field. Historically it doubled as
	// the schema version; that role now belongs solely to apiVersion. It is
	// retained only so legacy catalogs still parse and their value can be read
	// back through CatalogVersionString. The generator no longer emits it.
	//
	// Deprecated: use CatalogVersion for content versioning and apiVersion for
	// the schema version.
	Version    string    `json:"version,omitempty" yaml:"version,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt" yaml:"updatedAt"`
	Repository string    `json:"repository" yaml:"repository"`
}

// CatalogVersionString returns the producer-owned catalog content version. For
// legacy catalogs that only populate the deprecated metadata.version field, that
// value is returned so existing catalogs keep displaying a version.
func (m CatalogMetadata) CatalogVersionString() string {
	if m.CatalogVersion != "" {
		return m.CatalogVersion
	}
	return m.Version
}

// UnsupportedAPIVersionError is returned when a catalog declares a schema/API
// version this build cannot load.
type UnsupportedAPIVersionError struct {
	APIVersion string
}

func (e *UnsupportedAPIVersionError) Error() string {
	return fmt.Sprintf(
		"unsupported catalog apiVersion %q: this build of gator supports %s; upgrade gator or regenerate the catalog with a supported version",
		e.APIVersion, strings.Join(SupportedAPIVersions(), ", "),
	)
}

// Bundle represents a curated set of policies with pre-configured constraints.
type Bundle struct {
	// Name is the unique identifier for this bundle (e.g., "pod-security-baseline").
	Name string `json:"name" yaml:"name"`
	// Description provides a human-readable summary of the bundle's purpose.
	Description string `json:"description" yaml:"description"`
	// Inherits specifies a parent bundle whose policies are included in this bundle.
	Inherits string `json:"inherits,omitempty" yaml:"inherits,omitempty"`
	// Policies lists policy names (not full Policy objects) included in this bundle.
	Policies []string `json:"policies" yaml:"policies"`
}

// Policy represents a single policy available in the catalog.
type Policy struct {
	// Name is the unique identifier for this policy, typically matching the ConstraintTemplate name.
	Name string `json:"name" yaml:"name"`
	// Version is the semantic version of this policy (e.g., "v1.2.3").
	Version string `json:"version" yaml:"version"`
	// Description provides a human-readable summary of what this policy enforces.
	Description string `json:"description" yaml:"description"`
	// Category groups related policies (e.g., "general", "pod-security").
	Category string `json:"category" yaml:"category"`
	// TemplatePath is the URL or relative path to the ConstraintTemplate YAML.
	TemplatePath string `json:"templatePath" yaml:"templatePath"`
	// BundleConstraints maps bundle names to their constraint file paths.
	// Different bundles may require different constraint configurations for the same template
	// (e.g., baseline vs restricted PSS profiles need different constraint values).
	BundleConstraints map[string]string `json:"bundleConstraints,omitempty" yaml:"bundleConstraints,omitempty"`
	// DocumentationURL links to external documentation for this policy.
	DocumentationURL string `json:"documentationUrl,omitempty" yaml:"documentationUrl,omitempty"`
	// Bundles lists which bundles include this policy (reverse reference for discovery).
	Bundles []string `json:"bundles,omitempty" yaml:"bundles,omitempty"`
}

// GetPolicy returns the policy with the given name, or nil if not found.
// Uses O(1) indexed lookup after first call. Thread-safe.
func (c *PolicyCatalog) GetPolicy(name string) *Policy {
	// Build index lazily on first lookup (thread-safe)
	c.policyIndexOnce.Do(func() {
		c.policyIndex = make(map[string]int, len(c.Policies))
		for i := range c.Policies {
			c.policyIndex[c.Policies[i].Name] = i
		}
	})
	if idx, ok := c.policyIndex[name]; ok {
		return &c.Policies[idx]
	}
	return nil
}

// GetBundle returns the bundle with the given name, or nil if not found.
// Uses O(1) indexed lookup after first call. Thread-safe.
func (c *PolicyCatalog) GetBundle(name string) *Bundle {
	// Build index lazily on first lookup (thread-safe)
	c.bundleIndexOnce.Do(func() {
		c.bundleIndex = make(map[string]int, len(c.Bundles))
		for i := range c.Bundles {
			c.bundleIndex[c.Bundles[i].Name] = i
		}
	})
	if idx, ok := c.bundleIndex[name]; ok {
		return &c.Bundles[idx]
	}
	return nil
}

// MaxInheritanceDepth is the maximum depth of bundle inheritance to prevent runaway expansion.
const MaxInheritanceDepth = 10

// ResolveBundlePolicies returns all policy names for a bundle, including inherited policies.
// Inheritance is processed parent-first (deepest ancestor first), so child policies can override.
func (c *PolicyCatalog) ResolveBundlePolicies(bundleName string) ([]string, error) {
	bundle := c.GetBundle(bundleName)
	if bundle == nil {
		return nil, &BundleNotFoundError{Name: bundleName}
	}

	// First, build the inheritance chain from child to ancestors
	var inheritanceChain []*Bundle
	visitedBundles := make(map[string]bool)
	current := bundle

	for current != nil {
		// Check for circular inheritance
		if visitedBundles[current.Name] {
			return nil, fmt.Errorf("circular inheritance detected in bundle: %s", current.Name)
		}
		visitedBundles[current.Name] = true

		// Check depth limit
		if len(inheritanceChain) >= MaxInheritanceDepth {
			return nil, fmt.Errorf("bundle inheritance exceeds maximum depth of %d", MaxInheritanceDepth)
		}

		inheritanceChain = append(inheritanceChain, current)

		if current.Inherits == "" {
			break
		}
		parent := c.GetBundle(current.Inherits)
		if parent == nil {
			return nil, &BundleNotFoundError{Name: current.Inherits}
		}
		current = parent
	}

	// Now process in reverse order (parent-first, deepest ancestor first)
	// This ensures parent policies are added first, and child policies can be deduplicated
	seen := make(map[string]bool)
	var policies []string

	for i := len(inheritanceChain) - 1; i >= 0; i-- {
		b := inheritanceChain[i]
		for _, p := range b.Policies {
			if !seen[p] {
				seen[p] = true
				policies = append(policies, p)
			}
		}
	}

	return policies, nil
}

// BundleNotFoundError is returned when a bundle cannot be found.
type BundleNotFoundError struct {
	Name string
}

func (e *BundleNotFoundError) Error() string {
	return "bundle not found: " + e.Name
}

// PolicyNotFoundError is returned when a policy cannot be found.
type PolicyNotFoundError struct {
	Name string
}

func (e *PolicyNotFoundError) Error() string {
	return "policy not found: " + e.Name
}
