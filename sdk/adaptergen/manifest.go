// SPDX-License-Identifier: Apache-2.0

// Package adaptergen creates a standalone reference adapter from public alpha contracts.
// The generated wrapper uses profilehttp; it is not an independent integration.
package adaptergen

import (
	_ "embed"
	"sort"

	"knowndevice.local/knowndevice/adapters/process"
	"knowndevice.local/knowndevice/sdk/credentialprofile"
	"knowndevice.local/knowndevice/sdk/device"
)

const (
	ManifestVersion  = "knowndevice-adapter/v1alpha1"
	ManifestSchemaID = "urn:knowndevice:adapter-manifest:v1alpha1"
)

// ManifestSchema validates both the unbound template and a concrete selected manifest.
//
//go:embed adapter.schema.json
var ManifestSchema []byte

type PermissionTemplate struct {
	NetworkOriginsFrom []string `json:"networkOriginsFrom"`
	FilesystemRead     []string `json:"filesystemRead"`
	FilesystemWrite    []string `json:"filesystemWrite"`
	SignerBroker       bool     `json:"signerBroker"`
}

// Template records supported contracts without claiming unknown endpoint permissions or pins.
type Template struct {
	APIVersion         string                     `json:"apiVersion"`
	Kind               string                     `json:"kind"`
	Name               string                     `json:"name"`
	Backend            string                     `json:"backend"`
	Scope              string                     `json:"scope"`
	ProtocolVersion    string                     `json:"protocolVersion"`
	ErrorVersion       string                     `json:"errorVersion"`
	Schemas            []process.SchemaIdentity   `json:"schemas"`
	CompositionID      string                     `json:"compositionId"`
	CompositionVersion int                        `json:"compositionVersion"`
	SupportedProfiles  []credentialprofile.Policy `json:"supportedProfiles"`
	Capabilities       []string                   `json:"capabilities"`
	Permissions        PermissionTemplate         `json:"permissions"`
	Limits             process.Limits             `json:"limits"`
}

// Manifest binds the template to exact public snapshot permissions and executable bytes.
// It describes selection; it does not establish backend conformance or OS isolation.
type Manifest struct {
	APIVersion         string                   `json:"apiVersion"`
	Kind               string                   `json:"kind"`
	Name               string                   `json:"name"`
	Backend            string                   `json:"backend"`
	Scope              string                   `json:"scope"`
	ProtocolVersion    string                   `json:"protocolVersion"`
	ErrorVersion       string                   `json:"errorVersion"`
	Schemas            []process.SchemaIdentity `json:"schemas"`
	CompositionID      string                   `json:"compositionId"`
	CompositionVersion int                      `json:"compositionVersion"`
	ArtifactDigest     string                   `json:"artifactDigest"`
	SnapshotDigest     string                   `json:"snapshotDigest"`
	CompositionDigest  string                   `json:"compositionDigest"`
	Profile            credentialprofile.Policy `json:"profile"`
	Capabilities       []string                 `json:"capabilities"`
	Permissions        process.Permissions      `json:"permissions"`
	Limits             process.Limits           `json:"limits"`
}

func referenceCapabilities() []string {
	caps := []string{"entitlement.authorize", "authority.issue", "authority.lookup", "authority.import", "authority.revoke", "authority.revocationStatus", "platform.register", "platform.registrationStatus", "transport.probe", "application.activate", "application.activationStatus", "withdrawal.withdraw", "withdrawal.status", "clock.assess"}
	for _, role := range []string{"entitlement", "authority", "platform", "transport", "application", "clock", "withdrawal"} {
		capability, _ := device.RequiredCapability(role)
		caps = append(caps, capability)
	}
	sort.Strings(caps)
	return caps
}

// Describe returns the fixed existing profilehttp reference composition policy.
func Describe(name string) (Template, error) {
	if !validName(name) {
		return Template{}, ErrOptions
	}
	reference, _ := credentialprofile.Find(credentialprofile.ReferenceID, 1)
	stable, _ := credentialprofile.Find(credentialprofile.StableID, 1)
	return Template{
		APIVersion: ManifestVersion, Kind: "template", Name: name,
		Backend: "profilehttp-reference", Scope: "fixture-reference-composition",
		ProtocolVersion: process.ProtocolVersion, ErrorVersion: process.ErrorVersion,
		Schemas:       []process.SchemaIdentity{process.Schema()},
		CompositionID: "local-http-process-lab", CompositionVersion: 1,
		SupportedProfiles: []credentialprofile.Policy{reference, stable},
		Capabilities:      referenceCapabilities(),
		Permissions:       PermissionTemplate{NetworkOriginsFrom: []string{"application", "control", "issuance", "transport"}, FilesystemRead: []string{}, FilesystemWrite: []string{}, SignerBroker: true},
		Limits:            process.DefaultLimits(),
	}, nil
}

// Bind refuses a snapshot or executable pin outside the implemented process composition.
// The caller must independently verify that artifactDigest identifies its selected file.
func Bind(name string, snapshot *device.PublicSnapshot, artifactDigest string) (Manifest, error) {
	template, err := Describe(name)
	if err != nil || snapshot == nil || snapshot.Validate() != nil || snapshot.Composition.ID != template.CompositionID || snapshot.Composition.Version != template.CompositionVersion || snapshot.Composition.ProcessArtifactDigest != artifactDigest {
		return Manifest{}, ErrManifest
	}
	permissions, err := process.ExpectedPermissions(snapshot)
	if err != nil {
		return Manifest{}, ErrManifest
	}
	return Manifest{
		APIVersion: template.APIVersion, Kind: "manifest", Name: name, Backend: template.Backend, Scope: template.Scope,
		ProtocolVersion: template.ProtocolVersion, ErrorVersion: template.ErrorVersion, Schemas: template.Schemas,
		CompositionID: template.CompositionID, CompositionVersion: template.CompositionVersion,
		ArtifactDigest: artifactDigest, SnapshotDigest: snapshot.Digest(), CompositionDigest: snapshot.Composition.Digest(),
		Profile: snapshot.Profile, Capabilities: template.Capabilities, Permissions: permissions, Limits: template.Limits,
	}, nil
}
