package acceptance_tests_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// kidOf returns the "kid" field from a JWT's header segment.
func kidOf(token string) string {
	parts := strings.Split(token, ".")
	Expect(parts).To(HaveLen(3), "malformed JWT")
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	Expect(err).NotTo(HaveOccurred(), "failed to base64url-decode JWT header")
	var header map[string]interface{}
	Expect(json.Unmarshal(headerJSON, &header)).To(Succeed())
	kid, ok := header["kid"].(string)
	Expect(ok).To(BeTrue(), "kid field not found or not a string in JWT header")
	return kid
}

// jwkWithKid returns the JWK entry whose "kid" field equals kid, failing the test if not found.
func jwkWithKid(keys []map[string]interface{}, kid string) map[string]interface{} {
	for _, k := range keys {
		if k["kid"] == kid {
			return k
		}
	}
	Fail(fmt.Sprintf("no JWK with kid=%q found in token_keys response", kid))
	return map[string]interface{}{} // unreachable; Fail above terminates the test
}

var _ = Describe("JWT signing through a remote signing plugin", func() {
	opsFile := "./opsfiles/enable-remote-signing.yml"

	BeforeEach(func() {
		deployUAAWithOpsFiles(opsFile)
	})

	It("issues a token that verifies against the published JWK", func() {
		token := obtainClientCredentialsToken()
		Expect(token).NotTo(BeEmpty())

		keys := fetchTokenKeys()
		var activeKey map[string]interface{}
		for _, k := range keys {
			if k["kid"] == "acceptance-test-key" {
				activeKey = k
				break
			}
		}
		Expect(activeKey).NotTo(BeNil(), "expected to find key with kid=acceptance-test-key in /token_keys")

		err := verifyTokenAgainstJWK(token, activeKey)
		Expect(err).NotTo(HaveOccurred(), "token signature verification failed")
	})

	It("publishes a JWK with no private key components", func() {
		keys := fetchTokenKeys()
		var activeKey map[string]interface{}
		for _, k := range keys {
			if k["kid"] == "acceptance-test-key" {
				activeKey = k
				break
			}
		}
		Expect(activeKey).NotTo(BeNil())

		Expect(activeKey).NotTo(HaveKey("d"), "JWK must not contain private exponent 'd'")
		Expect(activeKey).NotTo(HaveKey("p"), "JWK must not contain prime 'p'")
		Expect(activeKey).NotTo(HaveKey("q"), "JWK must not contain prime 'q'")
	})

	It("renders uaa.yml with no private key material and with signingKeyRef", func() {
		uaaYml := boshSSH("uaa", "sudo cat /var/vcap/jobs/uaa/config/uaa.yml")
		Expect(uaaYml).NotTo(BeEmpty(), "bosh ssh returned empty output for uaa.yml — check sudo permissions")
		Expect(uaaYml).NotTo(ContainSubstring("PRIVATE KEY"), "uaa.yml must not contain private key material")
		Expect(uaaYml).To(ContainSubstring("signingKeyRef: acceptance-test-key"), "uaa.yml must contain signingKeyRef")
	})

	It("has the remote signer socket file in place", func() {
		listing := boshSSH("uaa", "ls -l /var/vcap/sys/run/uaa/remote-signer.sock")
		Expect(listing).To(ContainSubstring("remote-signer.sock"))
	})

	Context("key rotation", func() {
		BeforeEach(func() {
			deployUAAWithOpsFiles("opsfiles/enable-remote-signing.yml",
				"opsfiles/enable-remote-signing-two-keys.yml")
		})

		It("publishes a new key before it is used to sign", func() {
			keys := fetchTokenKeys()
			kids := []string{}
			for _, k := range keys {
				kid, ok := k["kid"].(string)
				Expect(ok).To(BeTrue(), "JWK entry missing string 'kid' field")
				kids = append(kids, kid)
			}
			Expect(kids).To(ConsistOf("acceptance-test-key", "acceptance-test-key-2"))

			// Still signing with the original key.
			Expect(kidOf(obtainClientCredentialsToken())).To(Equal("acceptance-test-key"))
		})

		It("signs with the new key once it is made active, and old tokens still verify", func() {
			oldToken := obtainClientCredentialsToken()

			deployUAAWithOpsFiles(
				"opsfiles/enable-remote-signing.yml",
				"opsfiles/enable-remote-signing-two-keys.yml",
				"opsfiles/activate-second-key.yml")

			newToken := obtainClientCredentialsToken()
			Expect(kidOf(newToken)).To(Equal("acceptance-test-key-2"))

			// The previous key must remain published, or tokens issued before
			// the switch become unverifiable.
			allKeys := fetchTokenKeys()
			Expect(allKeys).To(HaveLen(2))
			Expect(verifyTokenAgainstJWK(oldToken, jwkWithKid(allKeys, "acceptance-test-key"))).To(Succeed())
		})
	})
})

// deployUAAWithOpsFiles is a thin alias over deployUAA.
func deployUAAWithOpsFiles(opsFiles ...string) {
	deployUAA(opsFiles...)
}

// uaaTLSClient returns an HTTP client that skips TLS verification, suitable
// for UAA deployments that use a self-signed certificate.
func uaaTLSClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// boshSSH runs cmd on the named instance via runCommandOnUaaViaSsh.
// It targets the `uaa` instance group; the instance argument is informational and currently ignored.
func boshSSH(_ string, cmd string) string {
	return runCommandOnUaaViaSsh(cmd)
}

// obtainClientCredentialsToken fetches an admin client_credentials token from UAA.
func obtainClientCredentialsToken() string {
	uaaIP, found := getUaaIP()
	Expect(found).To(BeTrue(), "UAA IP not found")

	storeData, err := os.ReadFile("/tmp/uaa-store.json")
	Expect(err).NotTo(HaveOccurred(), "could not read /tmp/uaa-store.json")

	var store map[string]interface{}
	Expect(json.Unmarshal(storeData, &store)).To(Succeed())

	adminSecret, ok := store["uaa_admin_client_secret"].(string)
	Expect(ok).To(BeTrue(), "uaa_admin_client_secret not found or not a string in store")

	tlsClient := uaaTLSClient()

	tokenURL := fmt.Sprintf("https://%s:8443/oauth/token", uaaIP)
	resp, err := tlsClient.PostForm(tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"admin"},
		"client_secret": {adminSecret},
	})
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK), "token endpoint returned non-200: %s", string(body))

	var tokenResp map[string]interface{}
	Expect(json.Unmarshal(body, &tokenResp)).To(Succeed())

	accessToken, ok := tokenResp["access_token"].(string)
	Expect(ok).To(BeTrue(), "access_token not found in token response")
	return accessToken
}

// fetchTokenKeys returns the keys array from UAA's /token_keys endpoint.
func fetchTokenKeys() []map[string]interface{} {
	uaaIP, found := getUaaIP()
	Expect(found).To(BeTrue(), "UAA IP not found")

	tlsClient := uaaTLSClient()

	keysURL := fmt.Sprintf("https://%s:8443/token_keys", uaaIP)
	resp, err := tlsClient.Get(keysURL)
	Expect(err).NotTo(HaveOccurred())
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	var keysResp map[string]interface{}
	Expect(json.Unmarshal(body, &keysResp)).To(Succeed())

	rawKeys, ok := keysResp["keys"].([]interface{})
	Expect(ok).To(BeTrue(), "keys field not found in /token_keys response")

	keys := make([]map[string]interface{}, 0, len(rawKeys))
	for _, k := range rawKeys {
		m, ok := k.(map[string]interface{})
		Expect(ok).To(BeTrue())
		keys = append(keys, m)
	}
	return keys
}

// verifyRS256 verifies an RS256 JWT signature against a public key.
func verifyRS256(token string, pub *rsa.PublicKey) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT: expected 3 parts, got %d", len(parts))
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig)
}

// verifyTokenAgainstJWK reconstructs the RSA public key from a JWK map and verifies the token.
func verifyTokenAgainstJWK(token string, jwk map[string]interface{}) error {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return fmt.Errorf("JWK missing 'n' field")
	}
	eStr, ok := jwk["e"].(string)
	if !ok {
		return fmt.Errorf("JWK missing 'e' field")
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return fmt.Errorf("failed to decode 'n': %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return fmt.Errorf("failed to decode 'e': %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	eInt64 := new(big.Int).SetBytes(eBytes).Int64()
	Expect(eInt64).To(BeNumerically(">", 0), "RSA public exponent must be positive")
	e := int(eInt64)

	pub := &rsa.PublicKey{N: n, E: e}
	return verifyRS256(token, pub)
}


