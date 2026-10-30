// SPDX-License-Identifier: Apache-2.0

package device

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestRoleIntervalRequiresOneCompleteAllowedPath(t *testing.T) {
	now := time.Now().UTC()
	leaf := &x509.Certificate{Raw: []byte("leaf"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	issuer := &x509.Certificate{Raw: []byte("allowed issuer"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	first := &x509.Certificate{Raw: []byte("first root"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Second)}
	second := &x509.Certificate{Raw: []byte("second root"), NotBefore: now.Add(2 * time.Second), NotAfter: now.Add(time.Hour)}
	role := RoleSnapshot{AllowedIssuers: []string{Hash(issuer.Raw)}}
	paths := [][]*x509.Certificate{{leaf, issuer, first}, {leaf, issuer, second}}
	latest := now.Add(3 * time.Second)
	if role.ValidateVerifiedPaths(paths, now) != nil || role.ValidateVerifiedPaths(paths, latest) != nil {
		t.Fatal("point validation must permit each independently valid path")
	}
	if role.ValidateVerifiedInterval(paths, now, latest) == nil {
		t.Fatal("disjoint paths concealed a trust gap")
	}
	complete := &x509.Certificate{Raw: []byte("continuous root"), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	paths = append(paths, []*x509.Certificate{leaf, issuer, complete})
	if err := role.ValidateVerifiedInterval(paths, now, latest); err != nil {
		t.Fatal("one complete allowed path refused")
	}
	for _, bounds := range [][2]time.Time{{{}, latest}, {latest, now}, {now, complete.NotAfter}} {
		if role.ValidateVerifiedInterval(paths, bounds[0], bounds[1]) == nil {
			t.Fatal("invalid or expired interval accepted")
		}
	}
	role.AllowedIssuers = []string{Hash([]byte("other issuer"))}
	if role.ValidateVerifiedInterval(paths, now, latest) == nil {
		t.Fatal("interval validity replaced issuer authorization")
	}
}
