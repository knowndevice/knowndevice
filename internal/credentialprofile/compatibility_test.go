// SPDX-License-Identifier: Apache-2.0

package credentialprofile

import (
	"testing"

	sdk "knowndevice.local/knowndevice/sdk/credentialprofile"
)

func TestPublicPolicyRetainsInternalTypeAndDigest(t *testing.T) {
	for _, id := range []string{ReferenceID, StableID} {
		policy, err := Find(id, 1)
		if err != nil {
			t.Fatal(err)
		}
		var public sdk.Policy = policy
		want, err := sdk.Find(id, 1)
		if err != nil || public != want {
			t.Fatal("public and internal policy identity differs")
		}
		if _, err = Resolve(public.ID, public.Version, public.PolicyDigest); err != nil {
			t.Fatal(err)
		}
	}
}
