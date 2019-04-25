// +skip_license_check

package nicapi

import (
	"os"
	"testing"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/stretchr/testify/assert"
)

var (
	liveTest bool
	apikey   string
	domain   string
)

func init() {
	apikey = os.Getenv("LUMASERV_API_KEY")
	domain = os.Getenv("LUMASERV_DOMAIN")
	if len(apikey) > 0 && len(domain) > 0 {
		liveTest = true
	}
}

func restoreCloudFlareEnv() {
	os.Setenv("LUMASERV_API_KEY", apikey)
}

func TestNewDNSProviderValid(t *testing.T) {
	os.Setenv("LUMASERV_API_KEY", "")
	_, err := NewDNSProviderCredentials("123", util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderValidEnv(t *testing.T) {
	os.Setenv("LUMASERV_API_KEY", "123")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.NoError(t, err)
	restoreCloudFlareEnv()
}

func TestNewDNSProviderMissingCredErr(t *testing.T) {
	os.Setenv("LUMASERV_API_KEY", "")
	_, err := NewDNSProvider(util.RecursiveNameservers)
	assert.EqualError(t, err, "credentials missing")
	restoreCloudFlareEnv()
}

func TestPresent(t *testing.T) {
	if !liveTest {
		t.Skip("skipping live test")
	}

	provider, err := NewDNSProviderCredentials(apikey, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.Present(domain, "_acme-challenge."+domain+".", "123d==")
	assert.NoError(t, err)
}

func TestCleanUp(t *testing.T) {
	if !liveTest {
		t.Skip("skipping live test")
	}

	time.Sleep(time.Second * 2)

	provider, err := NewDNSProviderCredentials(apikey, util.RecursiveNameservers)
	assert.NoError(t, err)

	err = provider.CleanUp(domain, "_acme-challenge."+domain+".", "123d==")
	assert.NoError(t, err)
}
