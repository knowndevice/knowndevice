{
  "subject": {"commonName": {{ toJson .Subject.CommonName }}},
  "sans": [],
  "keyUsage": ["digitalSignature"],
  "extKeyUsage": ["clientAuth"],
  "basicConstraints": {"isCA": false}
}
