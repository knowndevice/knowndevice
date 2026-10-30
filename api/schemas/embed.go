// SPDX-License-Identifier: Apache-2.0

// Package schemas embeds the alpha schemas used by the CLI.
package schemas

import _ "embed"

//go:embed device-config.schema.json
var DeviceConfig []byte

//go:embed plan.schema.json
var Plan []byte

//go:embed transition-receipt.schema.json
var TransitionReceipt []byte

//go:embed device-config-v1alpha2.schema.json
var DeviceConfigV2 []byte

//go:embed plan-v1alpha2.schema.json
var PlanV2 []byte

//go:embed transition-receipt-v1alpha2.schema.json
var TransitionReceiptV2 []byte

//go:embed process-v1alpha1.schema.json
var Process []byte
