// +skip_license_check

// This package implements a DNS provider for solving the DNS-01
// challenge using Lumaserv/NicAPI DNS.

// API Documentation: https://docs.nicapi.eu/de/docs/dns/zones#dns-zones

package nicapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
)

const APIURL = "https://connect.nicapi.eu/api/v1"

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	dns01Nameservers []string
	authKey          string
}

// NewDNSProvider returns a DNSProvider instance.
// Credentials must be passed in the environment variables
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	key := os.Getenv("LUMASERV_API_KEY")
	return NewDNSProviderCredentials(key, dns01Nameservers)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance.
func NewDNSProviderCredentials(key string, dns01Nameservers []string) (*DNSProvider, error) {
	if key == "" {
		return nil, fmt.Errorf("credentials missing")
	}

	return &DNSProvider{
		authKey:          key,
		dns01Nameservers: dns01Nameservers,
	}, nil
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, fqdn, value string) error {

	zone, err := c.getHostedZone(fqdn)
	if err != nil {
		return err
	}

	record, err := c.findTxtRecord(zone, fqdn)
	if err != nil && err != errNoExistingRecord {
		// this is a real error
		return err
	}

	recordName := strings.TrimSuffix(util.UnFqdn(fqdn), fmt.Sprintf(".%s", zone.Zone.Name))

	if record != nil {
		if record.Data == value {
			// the record is already set to the desired value
			return nil
		}

		record := dnsPostRecord{
			Zone: zone.Zone.Name,
			Records: []dnsRecord{
				{
					Name: recordName,
				},
			},
		}

		body, err := json.Marshal(record)
		if err != nil {
			return err
		}

		_, err = c.makeRequest("DELETE", "/dns/zones/records/delete", body)
		if err != nil {
			return err
		}
	}

	recCol := dnsPostRecord{
		Zone:    zone.Zone.Name,
		Records: []dnsRecord{
			{
				Name: recordName,
				TTL:  strconv.Itoa(120*60),
				Type: "TXT",
				Data: value,
			},

		},
	}

	body, err := json.Marshal(recCol)
	if err != nil {
		return err
	}

	_, err = c.makeRequest("POST", "/dns/zones/records/add", body)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, fqdn, value string) error {
	zone, err := c.getHostedZone(fqdn)
	if err != nil {
		return err
	}

	_, err = c.findTxtRecord(zone, fqdn)
	// Nothing to cleanup
	if err == errNoExistingRecord {
		return nil
	}
	if err != nil {
		return err
	}

	record := dnsPostRecord{
		Zone: zone.Zone.Name,
		Records: []dnsRecord{
			{
				Name: strings.TrimSuffix(util.UnFqdn(fqdn), fmt.Sprintf(".%s", zone.Zone.Name)),
			},
		},
	}

	body, err := json.Marshal(record)
	if err != nil {
		return err
	}

	_, err = c.makeRequest("DELETE", "/dns/zones/records/delete", body)
	if err != nil {
		return err
	}

	return nil
}

func (c *DNSProvider) getHostedZone(fqdn string) (*dnsZone, error) {

	authZone, err := util.FindZoneByFqdn(fqdn, c.dns01Nameservers)
	if err != nil {
		return nil, err
	}

	request := struct {
		Zone string `json:"zone"`
	}{
		util.UnFqdn(authZone),
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	result, err := c.makeRequest("GET", "/dns/zones/show", body)
	if err != nil {
		return nil, err
	}

	var hostedZone dnsZone
	err = json.Unmarshal(result, &hostedZone)
	if err != nil {
		return nil, err
	}

	return &hostedZone, nil
}

var errNoExistingRecord = errors.New("no existing record found")

func (c *DNSProvider) findTxtRecord(zone *dnsZone, fqdn string) (*dnsRecord, error) {

	name := strings.TrimSuffix(util.UnFqdn(fqdn), fmt.Sprintf(".%s", zone.Zone.Name))

	for _, rec := range zone.Zone.Records {
		if rec.Name == name {
			return &rec, nil
		}
	}

	return nil, errNoExistingRecord
}

func (c *DNSProvider) makeRequest(method, uri string, body []byte) (json.RawMessage, error) {

	// APIError contains error details for failed requests
	type APIMessage struct {
		Code    int    `json:"code,omitempty"`
		Message string `json:"message,omitempty"`
	}

	// APIResponse represents a response from API
	type APIResponse struct {
		MetaData struct {
			ClientTransactionId string `json:"clientTransactionId"`
			ServerTransactionId string `json:"serverTransactionId"`
		} `json:"metadata"`
		Messages struct {
			Errors   [] *APIMessage `json:"errors"`
			Warnings [] *APIMessage `json:"warnings"`
			Success  [] *APIMessage `json:"success"`
		} `json:"messages"`
		Status string          `json:"status"`
		Data   json.RawMessage `json:"data"`
	}

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", APIURL, uri), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("authToken", c.authKey)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)
	req.Header.Set("Content-Type", "application/json")

	fmt.Printf("HTTP Request: %s %s\n", method, fmt.Sprintf("%s%s", APIURL, uri))
	fmt.Printf("HTTP Body: %s\n", string(body))

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error querying API -> %v", err)
	}

	defer resp.Body.Close()

	var r APIResponse
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return nil, err
	}

	fmt.Printf("HTTP Transaction: %s\n", r.MetaData.ServerTransactionId)

	if r.Status != "success" {
		if len(r.Messages.Errors) > 0 {
			errStr := ""
			for _, apiErr := range r.Messages.Errors {
				errStr += fmt.Sprintf("\t Error: %d: %s", apiErr.Code, apiErr.Message)
			}
			return nil, fmt.Errorf("API Error \n%s", errStr)
		}
		return nil, fmt.Errorf("API error")
	}

	return r.Data, nil
}

// dnsRecord represents a DNS record
type dnsRecord struct {
	ID     int64  `json:"id,omitempty"`
	Name   string `json:"name"`
	TTL    string `json:"ttl,omitempty"`
	Type   string `json:"type"`
	Data   string `json:"data"`
	ZoneID string `json:"zone_id,omitempty"`
}

// dnsZone represents a DNS zone
type dnsZone struct {
	Zone struct {
		ID      int64        `json:"id"`
		Name    string       `json:"name"`
		Records [] dnsRecord `json:"records"`
	} `json:"zone"`
}

// dnsPostRecord represents the request data to create a new DNS record
type dnsPostRecord struct {
	Zone    string       `json:"zone"`
	Records [] dnsRecord `json:"records"`
}
