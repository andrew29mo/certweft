{{- $cr := .Insecure.CR -}}
{{- range $ext := $cr.Extensions -}}
{{- if eq (toJson $ext.ID) "\"2.5.29.17\"" -}}
{{- if ne (toJson $ext.Value) "\"MAuCCWxvY2FsaG9zdA==\"" -}}{{ fail "CW_NAME" }}{{- end -}}
{{- else if not (or (eq (toJson $ext.ID) "\"2.5.29.37\"") (eq (toJson $ext.ID) "\"2.5.29.19\"")) -}}{{ fail "CW_EXTENSION" }}{{- end -}}
{{- end -}}
{{- if ne (toJson $cr.DNSNames) "[\"localhost\"]" -}}{{ fail "CW_NAME" }}{{- end -}}
{{- if or (ne $cr.Subject.CommonName "localhost") (gt (len $cr.IPAddresses) 0) (gt (len $cr.EmailAddresses) 0) (gt (len $cr.URIs) 0) -}}{{ fail "CW_NAME" }}{{- end -}}
{{- if ne (toJson $cr.ExtKeyUsage) "[\"serverAuth\"]" -}}{{ fail "CW_EKU" }}{{- end -}}
{{- if gt (len $cr.UnknownExtKeyUsage) 0 -}}{{ fail "CW_EKU" }}{{- end -}}
{{- if not (typeIs "*ecdsa.PublicKey" $cr.PublicKey) -}}{{ fail "CW_KEY" }}{{- end -}}
{{- if ne (int $cr.PublicKey.Curve.Params.BitSize) 256 -}}{{ fail "CW_KEY" }}{{- end -}}
{{- if $cr.BasicConstraints -}}{{- if $cr.BasicConstraints.IsCA -}}{{ fail "CW_CA" }}{{- end -}}{{- end -}}
{"subject":{"commonName":"localhost"},"dnsNames":["localhost"],"keyUsage":["digitalSignature"],"extKeyUsage":["serverAuth"],"basicConstraints":{"isCA":false},"signatureAlgorithm":"ECDSA-SHA256"}
