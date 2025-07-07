package image_test

import (
	"context"
	"encoding/base64"
	"testing"
	
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/deckhouse/delivery-kit-sdk/pkg/signature/image"
	"github.com/deckhouse/delivery-kit-sdk/pkg/signver"
)

const (
	rootCA = `-----BEGIN CERTIFICATE-----
MIIFCzCCAvOgAwIBAgIUKbWkBKB3l3f1b9TXh5zHHk5cL58wDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKTXkgUm9vdCBDQTAeFw0yNTA3MDcwNzI4MTZaFw0zNTA3
MDUwNzI4MTZaMBUxEzARBgNVBAMMCk15IFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDq5sLeyuDAcm7Kuw//+E9rX00ilR6LOcIMdQYvxbzf
NO5R8fnzAl33BVGLIQf1xwBbFcS+kj8zBtqHJRfUxUWDDwjNl7lUnzSrh/F2e5zk
zgVhJreaM/t7HTNjn6YGPXU3FXMUO2yPD6utMEFaPS+/36GzE+fMiBlUEXLqVTB4
4IZ+W9vemicUZrABnfbpwOC/hcEnjDVha/lK5b9F1oHSknaY8hGnj3VJ9ryCCztm
ouCT0VV8jKuZNGc4SJ4jyjwxFbmGRgzzBnYeUYsPk4+18n1KxxXARHVy3i4v1lGe
vpgExHntAMdKADvOVG5Fp/lnN3z1uEQvbfn3Kmkgst+5+ODQGZbWIPtywxOuflA7
frREqAiIltuRfJ9t7NTIAW2fYlCyPgr1kihQUQRxcWrcD1IykxdbkCXL0l/NkjjQ
I+IVTVagumheBFpO4qYlqD4X0E7q2sNiJHnElWo9jIK4WclrJelrmrx4EQmeCBMF
GPvM3c3qx94Mv/Lb+LPqfQkpFQwo3DGT2Vp0DUBOYn1aTWYEm2DnyE2TgYZJh96O
1ZvL9pahOr1/jzheLofO/jHHAxA4QcnPPFkYw4ztOszGMi/A/VJ1BALDDgEdjVst
erqONULaYYIQovHl0fGfTG42cnjA6v3bhuL2Y9/bs+HNt0YdzRKTDd6oAbz9FiS9
fQIDAQABo1MwUTAdBgNVHQ4EFgQUSmyAMSbQMP/zEq//BfiPvWfBi+8wHwYDVR0j
BBgwFoAUSmyAMSbQMP/zEq//BfiPvWfBi+8wDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAHJbncwXY0VC8jnTGnP/uVV5z+z2dCiTgtR+DFItO8/Uw
iVSsXB/3b/VX/9y9qbtmxwyqqnnLdSWlrIzWLdbGi58xoVIgjfo6IxHq0Bjmewba
doLVBToRWERVIJbTTdb7hY6j2UbabLa2O+PJa1s9bVjJipmS0ubl9K1+INEHCufL
HuYvuo9s7BC6mLv5AHTMmntihrySGHTbzpYeiF1qovJM2Bv/Jqz2S7sxYJ5/BfKM
QsQx6mGAOTHXDpJ8FnWgJ5tPgStD78oVr4I2bEY+938QyQ22AG7CWaKqdrCzpd8M
dZWOuIg1KTp6X9ltLESAspO9JMSgOzMRLpwGTOgyySY4VBVGDSYVzdCrIXnj9dyH
9PFzyRJme3fV1F4m/+mG8vaahQCiZ05lJ+EG+s+ZiH4SX5vdFgWkfo4BN1yy/AD8
cXpHaLuCxIWQ5qEo5XG+sXtvi9U17oJ9GlkE1g/qdRjE7Si2P7pSntWf6iac/5AC
8dwowXDZJarAisZeaKtvPiC0L5aESRQ4zKcYIfpWj6nYeQ8b0UM4VUjf5/CFVUTv
um20EiI9oObZOFUQCiPkOaKUrrGE8zmMv/UH3ekoKPwtvNlOQIRNH+pZBu95hzUr
siZIf75iRd988awDMgP6YKZZ0qwXXYLTT9cl8RfCncu2mYM0SaRUnvy8ja0DYm8=
-----END CERTIFICATE-----`
	signerCert = `-----BEGIN CERTIFICATE-----
MIIEAjCCAeqgAwIBAgIURXZe/wmPd8m57M4xRz/wc4on04QwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKTXkgUm9vdCBDQTAeFw0yNTA3MDcwNzI4MjJaFw0yNjA3
MDcwNzI4MjJaMB0xGzAZBgNVBAMMEnNpZ25lckBleGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANOGEpBogYSdJ44H5gQNK8Y2dFo4VAWT
FN+h2TKATLQGvC+ncklIM5uqEMuud7I6x7N8436LP5wTcy0kHbYknKaNWPGPZv/s
OTEbvg35XkXllePr5wVzl2hmk0GfINaKquhmKqibJhb8+LJQdULoR0N51/SMMT35
SIIEJncj5IlCcMHEK1aH5RyemRe5V11lh4orNA4wPFN9mqZfUxf5nRqS+QFrJnTZ
cc2k7EerkHWJPpEdaTv2MwVmmRnPFe7x/gMySXu5bBfiG31cAPMF+Uj81xSGJFhj
5F8QDZl4mEX7CpAB7+HJ6WYP1E5xhOTq6WXwx9ratKxgcdG752frUYUCAwEAAaNC
MEAwHQYDVR0OBBYEFLReG2FZGaaIyvFKXaJmMeOkXpNGMB8GA1UdIwQYMBaAFEps
gDEm0DD/8xKv/wX4j71nwYvvMA0GCSqGSIb3DQEBCwUAA4ICAQBQzlt8LXJikAcz
m6ufQfyVHxWDxxknDZG7wjpirjJ8VCU356qTmhx+3rCmKTJqA3jDj/ge0TtFnUWY
yob/RSFdxnW/cbE1UoGMaJkbzVEdyYFkYiraxf4kyYYHVWlBZAOA8MmDZx1rr9Dq
wl8B5RmHNKwbfkp5oosxHMvNMknbrDVQeIeScjNxAO7/qsuhFIt5x/9YoY51ylvH
vlhLooUUNwnJRMpkDXYMyNf+v/m1vca7P45xYj+6kuSht66mdxIUkDHlQyH9ztOr
D3czrxEzwZCcrZJuCMG5+hozSTNdZnoEE/8hQkUJijvCSHPQZnGutDE7I6QhTOSt
M5C3tNE/YJZtOG+8Iir+gZZ8Ot0yqLinevVDGHaS5hAbU3T9EUisHcJbXXc+UzVl
f1n5PQ3dZXrVKQSdY5EoHqti8OCzoJY3DAkhMViUfsrERg6647b5wPjXk+VjaNoh
BRxzOMUCFwOu8d988BFMokFUu9UwAfoI/6UljAu364J2mcIN/S2lD9QpjHoebdJC
Ysp4deZhFRY/NTwk6sDdpNDDdT08Q3mEcU2mTYeWDDOTBMPUoA8m7/+Y4VFucbCM
rB6FflYnZMDbqf0aMcYGFugmjsN8Y2KoliNU5HKBWxC0n9JinNQ71DOyWkThGY7T
/ocVEDZ7SdtkIzKLBp/ZtcPlLor9gA==
-----END CERTIFICATE-----`
	signerKey = `-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----
eyJrZGYiOnsibmFtZSI6InNjcnlwdCIsInBhcmFtcyI6eyJOIjo2NTUzNiwiciI6
OCwicCI6MX0sInNhbHQiOiI2ZS9mcEU5SWZCNFJTdDU0cm1wZ1FranVXUlVuOHY5
d2VMU0E0R2twRmRnPSJ9LCJjaXBoZXIiOnsibmFtZSI6Im5hY2wvc2VjcmV0Ym94
Iiwibm9uY2UiOiJRWTVPaGhCRXhUVVB0K2U2ZHJpaDJqb0xrTnpCYUg5byJ9LCJj
aXBoZXJ0ZXh0IjoiYkVUWkZVZjdDZUdZSVREMmlWMFVaZVVKZnh5bmttK2ZaVDF1
WVgzdG5KU2diUFFYb3o4cEUrMjVlelNzMUlxeHRJVm4xbVFrNGZmMkFqaUxtZ0FE
eWo5Ky9LTDZ1c1Uza21vaVNGWUlDbGQxTittQ2xsZDNUK3J0TFpDZjVsZkdVYUVM
T2MwcityTEVJeXdYYXZWbVR1Qm5qYisvVXg2d2dQRTE5bE9BM1RBOE1WNEdjcEFG
TGozVCthcjFlUVV0R1NzeWFHSWU3UUYxOUdaRmJjRENocXZOZkltRnJwYjQ3WXVs
VUVrbDNLbVVYSnpYUXpLUTA0UWRscmxEVUh5ZXlXcHdyYmc1aWx2dktBQUN5ek5P
bmx4RUxmWGlNVXpPY3FGb3Q3YVVxRmtnazZrYmlrMGJ2emJOd05lc0gxOTduOXN4
blUyTS9IbmVsQmxjTlc5YXBlTWJhUmZlWEUrV2labGw1WDhkMmJTR3FXS3FXSEc3
cXAvNFZ5eXBxWjJBNXJ6a0l4UWNnZ3hJQjQyTERuaCtaOHZXQ29WaVYrR05IRkdr
SG1FUnFVM0dPSmgxb0dhbWtuS0Z6V3FlL09meDlEUUJ3L0NDU3hoNFRtYXduVlg2
SkdSV3NhUW1LRXVtMUhWWGdSYzZXWEZzQ3FuV01JNVh0UE1IQnY3N0pwaDU5UTlq
OUxVS1VxeENTUzFuQm12bXBnelBuZDNGOUdITlc4c2xYVExlRWNuN3ZETzNiWUh4
WUJpNklVZ1RUNWpDVkxaM2I4WXd1WUNmYUJWa0h5ZGM3NTNYakp3bHZjTkZabHN6
T2xsMkxHenpDalI4eVgydU1OblNpU2xYKzNYbjM1TkE3MlhQZEFURnNmTUxpNUh2
eW4zcG1rVTJHM2gvVjl3ZXVzYWZmaisxZjFjVGN1Zk9HV2xQQkVsM0M1SEIySEE0
Mk9UU25DK0JNQjdjUStKUC9SUVlEOTJMV0NIR3pMMG1YSHE2ZTJLQnJ4L3MrZ0Jq
d082T0ZkalA0RkVNSUx4UGVJWWhKSGszWG9lU3Q0VTRSVkpUQWxGWTc5YlZSSVpx
d1lEZC9KSUZhVCtiRVY0N1FvWFNRZmdxU0FSVTJlVTRmNkszT1Q2eFJTVGY3WEhv
ek1MSDNycmZyYmZVUFFUdmJpUUkvb0hDc1pLYjRnVkhHUE1EV29aNlpaMDV3QjVs
dUZXMFdsdnZMRWw0ajJlZGxDOEV3QllocW85TlloMldKaFFlMFUxbk9mQnhCaVVT
R0pxc2p6TUtPZW16NklMbkdKTnRoR203ZVdCbi84UE5DSGF1NmFOb0dSeEZlUEVV
OG4xaVo4MWkxdmtobUJBUzZaVGpxUlJ2OTFVOGFlTytFcnFEWFlOME43VXdKUlB6
TEJvRTE1U0txMnVJdGdidnRBNmZ0cGMwYXR1VXlFSUxKalVnK3NZNFJHdkdEREpJ
UkNLbVI5dFl2SklVUjBvQ3dUd1U0NkdBY0pDbE10R0FLRGlsT0JMcHpUSlJxYVpH
bFhMQk9jK25MSWticHU2ZnY0clJmalQ2MGtmUVYrU0JXUUE3emtTL2w5Y0JVa0xt
NGN0NmNCTm9GdG5FTzJCeEJSUE1SMkoyRWI4OGxUSVpDa2MyUFJUbjRLUEpLUm5K
bW93SVdvS1BMRkV6V2FyTVkxWTdTTEJSMGhlYUZkMUUydExSeUo4cEpoakdENkx1
bUVEN3BSY09pYjQvQTliYkVPUXhqZlRxNWxHZWdlVHVwZnpHUk1raWM3dW9hSE1G
Wjl5YWNBNy9wUDhTM0ticUJnMkFIck4wWHZERm1BaWw1aFBGVVQvOG50U1Q4bHpu
NVBlZElXNWUyR3VBa01BSXNWcnAzY2FGNWMvOGRDZ2hiVGVlN3VlRkhjQ0lkQUdo
U3RWZDQwbnJQa09ZUTc1anhneHlCbVUvSHFYdTkxRXNsTVAvYnNpRzZSWEllakxF
SVNhRXpXZUlpRGtmeFhPSzMyRnBlblR3VHRTS1I3eXVpMUVxMTBrQlQxYmdKS3ln
UmhHcnAwL0xhb0hxNUQzczYyZ3gzRjg0ZXQrRjNpWFJWcFJkdWhnWGZ3VEZpK0dS
R3IwT2NVUTBxaFpaOXB4QitTTG1oT3YwYnhKNWEvcHBPRFVvUzZvOXlBZkE2Q01z
bUhiRW1TZ3ZEMHRjYW55UkRYMjhBQUdDdnpVPSJ9
-----END ENCRYPTED SIGSTORE PRIVATE KEY-----`
)

func TestName(t *testing.T) {
	sv, err := signver.NewSignerVerifier(
		context.Background(),
		base64.StdEncoding.EncodeToString([]byte(signerCert)),
		"",
		signver.KeyOpts{
			KeyRef: base64.StdEncoding.EncodeToString([]byte(signerKey)),
		},
	)
	if err != nil {
		t.Fatalf("failed to create signer verifier: %v", err)
	}
	
	imageRef := "nginx:latest"

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		t.Fatalf("failed to parse image reference: %v", err)
	}
	
	r, err := remote.Get(ref)
	if err != nil {
		t.Fatalf("failed to get image: %v", err)
	}
	
	i, err := r.Image()
	if err != nil {
		t.Fatalf("failed to get image: %v", err)
	}
	
	m, err := i.Manifest()
	if err != nil {
		t.Fatalf("failed to get manifest: %v", err)
	}
	
	annotations, err := image.GetSignatureAnnotationsForImageManifest(context.Background(), sv, m)
	if err != nil {
		t.Fatalf("failed to get signature annotations: %v", err)
	}
	
	img := mutate.Annotations(i, annotations).(v1.Image)
	
	m, err = img.Manifest()
	if err != nil {
		t.Fatalf("failed to get manifest after mutation: %v", err)
	}
	
	if err := image.VerifyImageManifestSignature(context.Background(), base64.StdEncoding.EncodeToString([]byte(rootCA)), m); err != nil {
		t.Fatalf("failed to verify image manifest signature: %v", err)
	}
}
