package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

const defaultApiKeyConfigFile = "../config/config-default-apiKey.json"
const defaultApiTokenConfigFile = "../config/config-default-apiToken.json"

func TestLoadConfigError(t *testing.T) {
	config, err := loadConfig("dummy.json")
	assert.Error(t, err)
	assert.IsType(t, Config{}, config)
}

func TestLoadConfigApiKey(t *testing.T) {
	defaultConfig := Config{}
	defaultConfig.Cloudflare.ApiKey = "key"
	defaultConfig.Cloudflare.Email = "my@email.com"
	defaultConfig.DNS.Zone = "domain.com"
	defaultConfig.DNS.Record = "subdomain"

	config, err := loadConfig(defaultApiKeyConfigFile)
	require.NoError(t, err)
	assert.IsType(t, Config{}, config)
	assert.Equal(t, defaultConfig, config)
}

func TestLoadConfigApiToken(t *testing.T) {
	defaultConfig := Config{}
	defaultConfig.Cloudflare.ApiToken = "token"
	defaultConfig.DNS.Zone = "domain.com"
	defaultConfig.DNS.Record = "subdomain"

	config, err := loadConfig(defaultApiTokenConfigFile)
	require.NoError(t, err)
	assert.IsType(t, Config{}, config)
	assert.Equal(t, defaultConfig, config)
}

func TestGetExternalIP(t *testing.T) {
	ip, err := getExternalIP()

	require.NoError(t, err)
	assert.IsType(t, IP{}, ip)
}

func TestGetIPFormat(t *testing.T) {
	ipv4 := net.ParseIP("127.0.0.1")
	ipv6 := net.ParseIP("::1")

	ipv4Format, err := getIPFormat(ipv4)
	require.NoError(t, err)
	assert.Equal(t, net.IPv4len, ipv4Format)

	ipv6Format, err := getIPFormat(ipv6)
	require.NoError(t, err)
	assert.Equal(t, net.IPv6len, ipv6Format)

	_, err = getIPFormat(net.ParseIP("2.2.1"))
	require.Error(t, err)
}

func TestGetCurrentDNSIP(t *testing.T) {
	ip, err := getCurrentDNSIP("localhost")

	require.NoError(t, err)
	assert.IsType(t, IP{}, ip)
	if ip.Format == net.IPv4len {
		assert.Equal(t, "127.0.0.1", ip.String)
		assert.Equal(t, net.IPv4len, ip.Format)
	} else if ip.Format == net.IPv6len {
		assert.Equal(t, "::1", ip.String)
		assert.Equal(t, net.IPv6len, ip.Format)
	} else {
		assert.Failf(t, "Invalid IP Format found", "IP found like: %v", ip)
	}


	_, err = getCurrentDNSIP("not.valid.dns")
	require.Error(t, err)
}

func TestInitializeLog(t *testing.T) {
	testLogFile := "/tmp/test.log"
	logFile, err := initializeLog(testLogFile)

	require.NoError(t, err)
	assert.IsType(t, &os.File{}, logFile)
	assert.FileExists(t, testLogFile)

	_, err = initializeLog("/tmp/")
	require.Error(t, err)
}

func TestGetDNSRecordType(t *testing.T) {
	ipv4, err := getDNSRecordType(IP{Format: net.IPv4len})
	require.NoError(t, err)
	assert.Equal(t, "A", ipv4)

	ipv6, err := getDNSRecordType(IP{Format: net.IPv6len})
	require.NoError(t, err)
	assert.Equal(t, "AAAA", ipv6)

	ipvInvalid, err := getDNSRecordType(IP{Format: 10})
	require.Error(t, err)
	assert.Equal(t, "", ipvInvalid)
}

/**
 * Cloudflare Server Mocking
 * @see https://github.com/cloudflare/cloudflare-go/blob/master/cloudflare_test.go
 */
var (
	// mux is the HTTP request multiplexer used with the test server.
	mux *http.ServeMux

	// client is the API client being tested
	client *cloudflare.API

	// server is a test HTTP server used to provide mock API responses
	server *httptest.Server
)

func setup(opts ...cloudflare.Option) {
	// test server
	mux = http.NewServeMux()
	server = httptest.NewServer(mux)

	// disable rate limits and retries in testing - prepended so any provided value overrides this
	opts = append([]cloudflare.Option{cloudflare.UsingRateLimit(100000), cloudflare.UsingRetryPolicy(0, 0, 0)}, opts...)

	// Cloudflare client configured to use test server
	client, _ = cloudflare.New("deadbeef", "cloudflare@example.org", opts...)
	client.BaseURL = server.URL
}

func teardown() {
	server.Close()
}

func TestCloudflareConnect(t *testing.T) {
	defaultTokenConfig := Config{}
	defaultTokenConfig.Cloudflare.ApiToken = "token"
	defaultTokenConfig.DNS.Zone = "domain.com"
	defaultTokenConfig.DNS.Record = "subdomain"
	api, err := cloudflareConnect(defaultTokenConfig)
	require.NoError(t, err)
	assert.IsType(t, &cloudflare.API{}, api)

	defaultKeyConfig := Config{}
	defaultKeyConfig.Cloudflare.ApiKey = "key"
	defaultKeyConfig.Cloudflare.Email = "my@email.com"
	defaultKeyConfig.DNS.Zone = "domain.com"
	defaultKeyConfig.DNS.Record = "subdomain"
	api, err = cloudflareConnect(defaultKeyConfig)
	require.NoError(t, err)
	assert.IsType(t, &cloudflare.API{}, api)

	invalidConfig := Config{}
	invalidConfig.DNS.Zone = "domain.com"
	invalidConfig.DNS.Record = "subdomain"
	api, err = cloudflareConnect(invalidConfig)
	require.Error(t, err)
	assert.IsType(t, &cloudflare.API{}, api)
}

func TestCloudflareGetZoneIDSuccess(t *testing.T) {
	setup()
	defer teardown()

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method, "Expected method 'GET', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "example.com", r.URL.Query()["name"][0])

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		// Response from https://api.cloudflare.com/#zone-list-zones
		fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": [\n    {\n      \"id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n      \"name\": \"example.com\",\n      \"development_mode\": 7200,\n      \"original_name_servers\": [\n        \"ns1.originaldnshost.com\",\n        \"ns2.originaldnshost.com\"\n      ],\n      \"original_registrar\": \"GoDaddy\",\n      \"original_dnshost\": \"NameCheap\",\n      \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n      \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n      \"activated_on\": \"2014-01-02T00:01:00.12345Z\",\n      \"owner\": {\n        \"id\": \"\",\n        \"email\": \"\",\n        \"type\": \"user\"\n      },\n      \"account\": {\n        \"id\": \"01a7362d577a6c3019a474fd6f485823\",\n        \"name\": \"Demo Account\"\n      },\n      \"permissions\": [\n        \"#zone:read\",\n        \"#zone:edit\"\n      ],\n      \"plan\": {\n        \"id\": \"e592fd9519420ba7405e1307bff33214\",\n        \"name\": \"Pro Plan\",\n        \"price\": 20,\n        \"currency\": \"USD\",\n        \"frequency\": \"monthly\",\n        \"legacy_id\": \"pro\",\n        \"is_subscribed\": true,\n        \"can_subscribe\": true\n      },\n      \"plan_pending\": {\n        \"id\": \"e592fd9519420ba7405e1307bff33214\",\n        \"name\": \"Pro Plan\",\n        \"price\": 20,\n        \"currency\": \"USD\",\n        \"frequency\": \"monthly\",\n        \"legacy_id\": \"pro\",\n        \"is_subscribed\": true,\n        \"can_subscribe\": true\n      },\n      \"status\": \"active\",\n      \"paused\": false,\n      \"type\": \"full\",\n      \"name_servers\": [\n        \"tony.ns.cloudflare.com\",\n        \"woz.ns.cloudflare.com\"\n      ]\n    }\n  ]\n}")
	})

	zoneID, err := cloudflareGetZoneID(client, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "023e105f4ecef8ad9ca31a8372d0c353", zoneID)
}
func TestCloudflareGetZoneIDError(t *testing.T) {
	setup()
	defer teardown()

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method, "Expected method 'GET', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "example.com", r.URL.Query()["name"][0])

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(403)
		fmt.Fprintf(w,"Error")
	})

	_, err = cloudflareGetZoneID(client, "example.com")
	require.Error(t, err)
}

func TestCloudflareGetDNSRecordSuccess(t *testing.T) {
	setup()
	defer teardown()

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method, "Expected method 'GET', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "example.com", r.URL.Query()["name"][0])

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		// Response from https://api.cloudflare.com/#dns-records-for-a-zone-list-dns-records
		fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": [\n    {\n      \"id\": \"372e67954025e0ba6aaa6d586b9e0b59\",\n      \"type\": \"A\",\n      \"name\": \"example.com\",\n      \"content\": \"198.51.100.4\",\n      \"proxiable\": true,\n      \"proxied\": false,\n      \"ttl\": 120,\n      \"locked\": false,\n      \"zone_id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n      \"zone_name\": \"example.com\",\n      \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n      \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n      \"data\": {},\n      \"meta\": {\n        \"auto_added\": true,\n        \"source\": \"primary\"\n      }\n    }\n  ]\n}")
	})

	records, err := cloudflareGetDNSRecord(client, "023e105f4ecef8ad9ca31a8372d0c353", "example.com")
	require.NoError(t, err)
	assert.Equal(t, "372e67954025e0ba6aaa6d586b9e0b59", records[0].ID)
}
func TestCloudflareGetDNSRecordError(t *testing.T) {
	setup()
	defer teardown()

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method, "Expected method 'GET', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "example.com", r.URL.Query()["name"][0])

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(403)
		fmt.Fprintf(w,"Error")
	})

	_, err = cloudflareGetDNSRecord(client, "023e105f4ecef8ad9ca31a8372d0c353", "example.com")
	require.Error(t, err)
}

func TestCloudflareCreateDNSSuccess(t *testing.T) {
	setup()
	defer teardown()

	expectedBody := cloudflare.DNSRecord{
		ID:         "",
		Type:       "A",
		Name:       "example.com",
		Content:    "127.0.0.1",
		Proxiable:  false,
		Proxied:    false,
		TTL:        120,
		Locked:     false,
		ZoneID:     "",
		ZoneName:   "",
		CreatedOn:  time.Time{},
		ModifiedOn: time.Time{},
		Data:       nil,
		Meta:       nil,
		Priority:   0,
	}

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method, "Expected method 'POST', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode Request Body
		decoder := json.NewDecoder(r.Body)
		var data cloudflare.DNSRecord
		decoder.Decode(&data)
		assert.Equal(t, expectedBody, data)

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		// Response from https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
		fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": {\n    \"id\": \"372e67954025e0ba6aaa6d586b9e0b59\",\n    \"type\": \"A\",\n    \"name\": \"example.com\",\n    \"content\": \"198.51.100.4\",\n    \"proxiable\": true,\n    \"proxied\": false,\n    \"ttl\": 120,\n    \"locked\": false,\n    \"zone_id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n    \"zone_name\": \"example.com\",\n    \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"data\": {},\n    \"meta\": {\n      \"auto_added\": true,\n      \"source\": \"primary\"\n    }\n  }\n}")
	})

	_, err = cloudflareCreateDNS(client, "example.com", IP{
		String: "127.0.0.1",
		Format: net.IPv4len,
	}, "023e105f4ecef8ad9ca31a8372d0c353")
	require.NoError(t, err)

	_, err = cloudflareCreateDNS(client, "example.com", IP{
		String: "127.0.0.1",
		Format: 10,
	}, "023e105f4ecef8ad9ca31a8372d0c353")
	require.Error(t, err)
}
func TestCloudflareCreateDNSError(t *testing.T) {
	setup()
	defer teardown()

	expectedBody := cloudflare.DNSRecord{
		ID:         "",
		Type:       "A",
		Name:       "example.com",
		Content:    "127.0.0.1",
		Proxiable:  false,
		Proxied:    false,
		TTL:        120,
		Locked:     false,
		ZoneID:     "",
		ZoneName:   "",
		CreatedOn:  time.Time{},
		ModifiedOn: time.Time{},
		Data:       nil,
		Meta:       nil,
		Priority:   0,
	}

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method, "Expected method 'POST', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode Request Body
		decoder := json.NewDecoder(r.Body)
		var data cloudflare.DNSRecord
		decoder.Decode(&data)
		assert.Equal(t, expectedBody, data)

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(403)
		fmt.Fprintf(w,"Error")
	})

	_, err = cloudflareCreateDNS(client, "example.com", IP{
		String: "127.0.0.1",
		Format: net.IPv4len,
	}, "023e105f4ecef8ad9ca31a8372d0c353")
	require.Error(t, err)
}

func TestCloudflareUpdateDNSSuccess(t *testing.T) {
	setup()
	defer teardown()

	expectedBody := cloudflare.DNSRecord{
		ID:         "",
		Type:       "A",
		Name:       "example.com",
		Content:    "127.0.0.1",
		Proxiable:  false,
		Proxied:    false,
		TTL:        120,
		Locked:     false,
		ZoneID:     "",
		ZoneName:   "",
		CreatedOn:  time.Time{},
		ModifiedOn: time.Time{},
		Data:       nil,
		Meta:       nil,
		Priority:   0,
	}

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/372e67954025e0ba6aaa6d586b9e0b59", func(w http.ResponseWriter, r *http.Request) {
		// Cloudlfare api.UpdateDNSRecord does a "api.DNSRecord(zoneID, recordID)", before updating...
		if r.Method == "GET" {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": {\n    \"id\": \"372e67954025e0ba6aaa6d586b9e0b59\",\n    \"type\": \"A\",\n    \"name\": \"example.com\",\n    \"content\": \"198.51.100.4\",\n    \"proxiable\": true,\n    \"proxied\": false,\n    \"ttl\": 120,\n    \"locked\": false,\n    \"zone_id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n    \"zone_name\": \"example.com\",\n    \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"data\": {},\n    \"meta\": {\n      \"auto_added\": true,\n      \"source\": \"primary\"\n    }\n  }\n}")
			return
		}

		assert.Equal(t, "PATCH", r.Method, "Expected method 'PATCH', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode Request Body
		decoder := json.NewDecoder(r.Body)
		var data cloudflare.DNSRecord
		decoder.Decode(&data)
		assert.Equal(t, expectedBody, data)

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(200)
		// Response from https://api.cloudflare.com/#dns-records-for-a-zone-patch-dns-record
		fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": {\n    \"id\": \"372e67954025e0ba6aaa6d586b9e0b59\",\n    \"type\": \"A\",\n    \"name\": \"example.com\",\n    \"content\": \"198.51.100.4\",\n    \"proxiable\": true,\n    \"proxied\": false,\n    \"ttl\": 120,\n    \"locked\": false,\n    \"zone_id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n    \"zone_name\": \"example.com\",\n    \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"data\": {},\n    \"meta\": {\n      \"auto_added\": true,\n      \"source\": \"primary\"\n    }\n  }\n}")
	})

	err = cloudflareUpdateDNS(client, IP{
		String: "127.0.0.1",
		Format: net.IPv4len,
	}, "023e105f4ecef8ad9ca31a8372d0c353", "372e67954025e0ba6aaa6d586b9e0b59")
	require.NoError(t, err)

	err = cloudflareUpdateDNS(client, IP{
		String: "127.0.0.1",
		Format: 10,
	}, "023e105f4ecef8ad9ca31a8372d0c353", "372e67954025e0ba6aaa6d586b9e0b59")
	require.Error(t, err)
}
func TestCloudflareUpdateDNSError(t *testing.T) {
	setup()
	defer teardown()

	expectedBody := cloudflare.DNSRecord{
		ID:         "",
		Type:       "A",
		Name:       "example.com",
		Content:    "127.0.0.1",
		Proxiable:  false,
		Proxied:    false,
		TTL:        120,
		Locked:     false,
		ZoneID:     "",
		ZoneName:   "",
		CreatedOn:  time.Time{},
		ModifiedOn: time.Time{},
		Data:       nil,
		Meta:       nil,
		Priority:   0,
	}

	client, err := cloudflare.NewWithAPIToken("my-api-token")
	assert.NoError(t, err)
	client.BaseURL = server.URL
	mux.HandleFunc("/zones/023e105f4ecef8ad9ca31a8372d0c353/dns_records/372e67954025e0ba6aaa6d586b9e0b59", func(w http.ResponseWriter, r *http.Request) {
		// Cloudlfare api.UpdateDNSRecord does a "api.DNSRecord(zoneID, recordID)", before updating...
		if r.Method == "GET" {
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(200)
			fmt.Fprintf(w, "{\n  \"success\": true,\n  \"errors\": [],\n  \"messages\": [],\n  \"result\": {\n    \"id\": \"372e67954025e0ba6aaa6d586b9e0b59\",\n    \"type\": \"A\",\n    \"name\": \"example.com\",\n    \"content\": \"198.51.100.4\",\n    \"proxiable\": true,\n    \"proxied\": false,\n    \"ttl\": 120,\n    \"locked\": false,\n    \"zone_id\": \"023e105f4ecef8ad9ca31a8372d0c353\",\n    \"zone_name\": \"example.com\",\n    \"created_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"modified_on\": \"2014-01-01T05:20:00.12345Z\",\n    \"data\": {},\n    \"meta\": {\n      \"auto_added\": true,\n      \"source\": \"primary\"\n    }\n  }\n}")
			return
		}

		assert.Equal(t, "PATCH", r.Method, "Expected method 'PATCH', got %s", r.Method)
		assert.Empty(t, r.Header.Get("X-Auth-Email"))
		assert.Empty(t, r.Header.Get("X-Auth-Key"))
		assert.Empty(t, r.Header.Get("X-Auth-User-Service-Key"))
		assert.Equal(t, "Bearer my-api-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Decode Request Body
		decoder := json.NewDecoder(r.Body)
		var data cloudflare.DNSRecord
		decoder.Decode(&data)
		assert.Equal(t, expectedBody, data)

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(403)
		fmt.Fprintf(w,"Error")
	})

	err = cloudflareUpdateDNS(client, IP{
		String: "127.0.0.1",
		Format: net.IPv4len,
	}, "023e105f4ecef8ad9ca31a8372d0c353", "372e67954025e0ba6aaa6d586b9e0b59")
	require.Error(t, err)
}

/**
 * Initialization Tests
 */
func ResetFlagsForTesting(usage func()) {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(ioutil.Discard) // Avoid flag.Usage() to write to sdterr
	flag.CommandLine.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Usage = usage
}

func TestInitializeNoParams(t *testing.T) {

	ResetFlagsForTesting(nil)

	config, logFile, err := initialize()

	require.Error(t, err)
	assert.Equal(t, flag.ErrHelp, err)
	assert.Equal(t, Config{}, config)
	assert.Equal(t, &os.File{}, logFile)
}

func TestInitializeOnlyLog(t *testing.T) {
	ResetFlagsForTesting(nil)

	flag.CommandLine.SetOutput(ioutil.Discard)
	os.Args = []string{"cmd", "-l", "/tmp/test.log"}
	config, logFile, err := initialize()

	require.Error(t, err)
	assert.Equal(t, flag.ErrHelp, err)
	assert.Equal(t, Config{}, config)
	assert.Equal(t, &os.File{}, logFile)
}

func TestInitializeOnlyConfig(t *testing.T) {
	ResetFlagsForTesting(nil)

	defaultConfig := Config{}
	defaultConfig.Cloudflare.ApiToken = "token"
	defaultConfig.DNS.Zone = "domain.com"
	defaultConfig.DNS.Record = "subdomain"

	flag.CommandLine.SetOutput(ioutil.Discard)
	os.Args = []string{"cmd", "-c", defaultApiTokenConfigFile}
	config, logFile, err := initialize()

	require.NoError(t, err)
	assert.IsType(t, Config{}, config)
	assert.IsType(t, &os.File{}, logFile)
	assert.Equal(t, defaultConfig, config)
	assert.Equal(t, os.Stdout.Name(), logFile.Name())
	assert.FileExists(t, logFile.Name())
}

func TestInitializeAllParamsInvalidLogfile(t *testing.T) {
	ResetFlagsForTesting(nil)

	flag.CommandLine.SetOutput(ioutil.Discard)
	os.Args = []string{"cmd", "-c", defaultApiTokenConfigFile, "-l", "/tmp/"}
	_, _, err := initialize()

	require.Error(t, err)
}

func TestInitializeAllParamsInvalidConfigFile(t *testing.T) {
	ResetFlagsForTesting(nil)

	flag.CommandLine.SetOutput(ioutil.Discard)
	os.Args = []string{"cmd", "-c", "/tmp/1"}
	_, _, err := initialize()

	require.Error(t, err)
}

func TestInitializeAllParams(t *testing.T) {
	ResetFlagsForTesting(nil)

	defaultConfig := Config{}
	defaultConfig.Cloudflare.ApiToken = "token"
	defaultConfig.DNS.Zone = "domain.com"
	defaultConfig.DNS.Record = "subdomain"

	logFileName := "/tmp/all.log"

	flag.CommandLine.SetOutput(ioutil.Discard)
	os.Args = []string{"cmd", "-c", defaultApiTokenConfigFile, "-l", logFileName}
	config, logFile, err := initialize()

	require.NoError(t, err)
	assert.IsType(t, Config{}, config)
	assert.IsType(t, &os.File{}, logFile)
	assert.Equal(t, defaultConfig, config)
	assert.Equal(t, logFileName, logFile.Name())
	assert.FileExists(t, logFileName)
}
