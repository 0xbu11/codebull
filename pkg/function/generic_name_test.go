//go:build !go1.27

package function

import "testing"

// A generic function is compiled once per shape, so what the source calls
// `defaultPolicy[V]` the binary calls `defaultPolicy[go.shape.string]`. A caller
// naming a location from source cannot know the shape, so the two forms have to
// meet somewhere — with the type arguments removed from both.
func TestStripTypeArgsMakesInstantiationsComparable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"source form", "ristretto.(*defaultPolicy[V]).Add", "ristretto.(*defaultPolicy[]).Add"},
		{"shape form", "github.com/x/ristretto/v2.(*defaultPolicy[go.shape.string]).Add", "github.com/x/ristretto/v2.(*defaultPolicy[]).Add"},
		{"two parameters", "pkg.(*Cache[go.shape.string,go.shape.string]).Set", "pkg.(*Cache[]).Set"},
		{"concrete instantiation", "pkg.(*Cache[string,string]).Set", "pkg.(*Cache[]).Set"},
		{"nested brackets in a type argument", "pkg.(*Store[map[string][]byte]).Put", "pkg.(*Store[]).Put"},
		{"no type arguments is untouched", "main.hot", "main.hot"},
		{"array type in the name survives as empty brackets", "main.take[4]", "main.take[]"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripTypeArgs(tc.in); got != tc.want {
				t.Fatalf("stripTypeArgs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The case this was written for: what the extension derives from the source has
// to reach what the compiler emitted. Two things differ at once — the type
// parameters became a shape, and the module's major-version suffix means the
// package the source calls "ristretto" appears as ".../ristretto/v2".
func TestSourceNameReachesCompiledInstantiation(t *testing.T) {
	const fromSource = "ristretto.(*defaultPolicy[V]).Add"
	const inBinary = "github.com/dgraph-io/ristretto/v2.(*defaultPolicy[go.shape.string]).Add"

	if nameMatches(inBinary, fromSource) {
		t.Fatal("precondition: the raw names should not match, or this test proves nothing")
	}
	if !looseMatches(inBinary, fromSource) {
		t.Fatalf("the source name still does not reach the compiled one:\n  %q\n  %q", inBinary, fromSource)
	}
}

// The major-version path breaks matching on its own, with no generics involved.
func TestMajorVersionModulePathAlone(t *testing.T) {
	const fromSource = "xxhash.Sum64String"
	const inBinary = "github.com/cespare/xxhash/v2.Sum64String"

	if nameMatches(inBinary, fromSource) {
		t.Fatal("precondition: a /v2 package name should not suffix-match")
	}
	if !looseMatches(inBinary, fromSource) {
		t.Fatal("a non-generic function in a /v2 module should still be found")
	}
}

// Widening must not make unrelated functions collide.
func TestLooseMatchingStaysSpecific(t *testing.T) {
	const wanted = "pkg.(*Cache[V]).Set"
	for _, other := range []string{
		"example.com/pkg.(*Cache[go.shape.string]).Get",   // different method
		"example.com/pkg.(*Policy[go.shape.string]).Set",  // different receiver
		"example.com/other.(*Cache[go.shape.string]).Set", // different package
		"example.com/pkg.(Cache[go.shape.string]).Set",    // value receiver, not pointer
	} {
		if looseMatches(other, wanted) {
			t.Fatalf("%q should not satisfy a request for %q", other, wanted)
		}
	}

	for _, ok := range []string{
		"example.com/pkg.(*Cache[go.shape.string]).Set",
		"example.com/pkg/v4.(*Cache[string,int]).Set",
	} {
		if !looseMatches(ok, wanted) {
			t.Fatalf("%q should satisfy a request for %q", ok, wanted)
		}
	}
}
