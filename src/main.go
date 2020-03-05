package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cloudflare/cloudflare-go"
	"github.com/glendc/go-external-ip"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
)

// Version of the Application, should be overwritten on compile
var Version = "v0.0.0"

// Config struct for the configuration file
type Config struct {
	Cloudflare struct {
		APIToken string `json:"apiToken"`
		APIKey   string `json:"apiKey"`
		Email    string `json:"email"`
	} `json:"cloudflare"`
	DNS struct {
		Zone   string `json:"name"`
		Record string `json:"record"`
	} `json:"dnsZone"`
}

// IP struct for better usage of IPs
type IP struct {
	String string
	Format int
}

// Loads Config file and returns a Config Struct
func loadConfig(file string) (Config, error) {
	var config Config
	configFile, err := os.Open(file)

	if err != nil {
		return Config{}, err
	}
	defer configFile.Close()

	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&config)
	if err != nil {
		return Config{}, err
	}

	return config, nil
}

// Try to retrieve the current external IP
func getExternalIP() (IP, error) {
	consensus := externalip.DefaultConsensus(nil, nil)
	ip, err := consensus.ExternalIP()
	if err != nil {
		return IP{}, err
	}

	ipFormat, err := getIPFormat(ip)
	if err != nil {
		return IP{}, err
	}

	return IP{String: ip.String(), Format: ipFormat}, nil
}

// Returns the IP Format for the given IP
func getIPFormat(ip net.IP) (int, error) {
	if p4 := ip.To4(); len(p4) == net.IPv4len {
		return net.IPv4len, nil
	}

	if len(ip) != net.IPv6len {
		return 0, errors.New("Invalid IP Format")
	}

	return net.IPv6len, nil
}

// Does a nslookup for given DNS and returns a IP Struct
func getCurrentDNSIP(dns string) (IP, error) {
	ips, err := net.LookupIP(dns)
	if err != nil {
		return IP{}, err
	}

	// We currently only want the first IP, if we got more than one
	curIP := ips[0]
	ipFormat, err := getIPFormat(curIP)
	if err != nil {
		return IP{}, err
	}

	return IP{String: curIP.String(), Format: ipFormat}, nil
}

// Returns the DNS Recordtype for the given IP
func getDNSRecordType(externalIP IP) (string, error) {
	switch externalIP.Format {
	case net.IPv4len:
		return "A", nil
	case net.IPv6len:
		return "AAAA", nil
	default:
		return "", errors.New("Unknown IP Format " + string(externalIP.Format))
	}
}

// Opens connection to Cloudflare API
func cloudflareConnect(config Config) (*cloudflare.API, error) {
	if config.Cloudflare.APIToken != "" {
		log.Debug("Connect to Cloudflare using APIToken")
		return cloudflare.NewWithAPIToken(config.Cloudflare.APIToken)
	} else if config.Cloudflare.APIKey != "" && config.Cloudflare.Email != "" {
		log.Debug("Connect to Cloudflare using APIKey")
		return cloudflare.New(config.Cloudflare.APIKey, config.Cloudflare.Email)
	}

	return &cloudflare.API{}, errors.New("no credentials provided")
}

// Returns the Cloudflare zoneID for the given DNSZone
func cloudflareGetZoneID(api *cloudflare.API, DNSZone string) (string, error) {
	log.Debugf("Retrieving ZoneID for Zone %s", DNSZone)
	zoneID, err := api.ZoneIDByName(DNSZone)
	if err != nil {
		return "", err
	}
	log.Debugf("Found ZoneID %s for Zone %s", zoneID, DNSZone)

	return zoneID, nil
}

// Returns the Cloudflare DNSRecord for the given DNS
func cloudflareGetDNSRecord(api *cloudflare.API, zoneID string, DNS string) ([]cloudflare.DNSRecord, error) {
	dnsRecord := cloudflare.DNSRecord{Name: DNS}
	log.Debugf("Search for DNS Record for DNS %s", DNS)
	records, err := api.DNSRecords(zoneID, dnsRecord)
	if err != nil {
		return []cloudflare.DNSRecord{}, err
	}

	return records, nil
}

// Created a new DNSRecord at Cloudflare
func cloudflareCreateDNS(api *cloudflare.API, DNS string, externalIP IP, zoneID string) (*cloudflare.DNSRecordResponse, error) {
	// Set the correct DNSRecordType
	recordType, err := getDNSRecordType(externalIP)
	if err != nil {
		return &cloudflare.DNSRecordResponse{}, err
	}

	dnsRecord := cloudflare.DNSRecord{
		Name:    DNS,
		Content: externalIP.String,
		Type:    recordType,
		Proxied: false,
		TTL:     120,
	}

	log.Debugf("Creating new DNS %s Record for %s to IP %s", recordType, DNS, externalIP.String)
	return api.CreateDNSRecord(zoneID, dnsRecord)
}

// Updates an existing DNS Record at Cloudflare
func cloudflareUpdateDNS(api *cloudflare.API, externalIP IP, zoneID string, recordID string) error {
	recordType, err := getDNSRecordType(externalIP)
	if err != nil {
		return err
	}

	return api.UpdateDNSRecord(zoneID, recordID, cloudflare.DNSRecord{Content: externalIP.String, Type: recordType, TTL: 120})
}

// Returns composed Destination DNS
func getDestDNS(config Config) string {
	if config.DNS.Record == "@" {
		return config.DNS.Zone
	}

	return config.DNS.Record + "." + config.DNS.Zone
}

// Initializes and sets the logger
func initializeLog(logFile string) (*os.File, error) {
	logFileFd, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return &os.File{}, fmt.Errorf("error opening file: %v", err)
	}
	log.SetOutput(logFileFd)

	return logFileFd, nil
}

// Initializes the Application (param parsing, logger and config parsing)
func initialize() (Config, *os.File, error) {
	// Overwrite default Usage()
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Cloudflare DynDNS - %s\n\n", Version)
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Parse CLI Params
	configFile := flag.String("c", "", "Use `file.json` as configuration file")
	logFile := flag.String("l", os.Stdout.Name(), "Use `logfile` as output")
	logLevel := flag.Int("ll", 1, "Sets log level (1=fatal, 2=error, 3=warn, 4=info, 5=debug)")

	flag.Parse()

	if *configFile == "" || *logFile == "" {
		flag.Usage()
		return Config{}, &os.File{}, flag.ErrHelp
	}

	// Initialize Logging
	logFileFd, err := initializeLog(*logFile)
	if err != nil {
		return Config{}, &os.File{}, err
	}

	// Load configuration
	config, err := loadConfig(*configFile)
	if err != nil {
		return Config{}, &os.File{}, err
	}

	// Sets the required log level
	switch *logLevel {
	case 1:
		log.SetLevel(log.FatalLevel)
	case 2:
		log.SetLevel(log.ErrorLevel)
	case 3:
		log.SetLevel(log.WarnLevel)
	case 4:
		log.SetLevel(log.InfoLevel)
	case 5:
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.FatalLevel)
	}

	return config, logFileFd, nil
}

func main() {
	config, logFile, err := initialize()

	if err != nil {
		// Don't print out if we want to show Usage()
		if err != flag.ErrHelp {
			log.Fatal(err)
		}

		return
	}
	defer logFile.Close()

	// Get external IP
	externalIP, err := getExternalIP()
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Debugf("Found externalIP: %s", externalIP.String)

	//Check if IP has changed
	destDNS := getDestDNS(config)
	currentIP, err := getCurrentDNSIP(destDNS)
	if err == nil && currentIP.String == externalIP.String {
		log.Infof("IP didn't change, exiting")
		return
	}
	if err != nil {
		log.Warnf("Nslookup didn't found IP, trying to check Cloudflare. Response was: %s", err)
	}

	api, err := cloudflareConnect(config)
	if err != nil {
		log.Fatal(err)
		return
	}

	zoneID, err := cloudflareGetZoneID(api, config.DNS.Zone)
	if err != nil {
		log.Fatal(err)
		return
	}

	// Search for Entry at Cloudflare
	records, err := cloudflareGetDNSRecord(api, zoneID, destDNS)
	if err != nil {
		log.Fatal(err)
		return
	}

	if len(records) <= 0 {
		log.Debugf("DNSRecord not found, try to create new entry for %s", destDNS)
		_, err = cloudflareCreateDNS(api, destDNS, externalIP, zoneID)
		if err != nil {
			log.Fatal(err)
			return
		}

		log.Info("DNS Successfully created!")
		return
	}

	log.Debugf("Found record of Type %s", records[0].Type)
	if records[0].Content == externalIP.String {
		log.Debugf("IP didn't change, exiting")
		return
	}

	err = cloudflareUpdateDNS(api, externalIP, zoneID, records[0].ID)
	if err != nil {
		log.Fatal(err)
		return
	}
	log.Infof("Record %s updated successfully with IP %s!", destDNS, externalIP.String)
}
