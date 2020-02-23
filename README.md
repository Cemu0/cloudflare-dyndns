[![pipeline status](https://gitlab.com/_p0l0_/cloudflare-dyndns/badges/master/pipeline.svg)](https://gitlab.com/_p0l0_/cloudflare-dyndns/commits/master) [![coverage report](https://gitlab.com/_p0l0_/cloudflare-dyndns/badges/master/coverage.svg)](https://gitlab.com/_p0l0_/cloudflare-dyndns/commits/master) [![Go Report Card](https://goreportcard.com/badge/gitlab.com/_p0l0_/cloudflare-dyndns)](https://goreportcard.com/report/gitlab.com/_p0l0_/cloudflare-dyndns) [![License MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://img.shields.io/badge/License-MIT-brightgreen.svg)

# Cloudflare DynDNS Client

A DynDNS Client using Cloudflare API

## Configuration
Configuration needs to be saved as a JSON File. Examples can be found under _config_ folder.

If you are using the new Cloudflare API Token:

```json
{
   "cloudflare": {
     "apiToken": "token"
   },
   "dnsZone": {
     "name": "domain.com",
     "record": "subdomain"
   }
 }
```

For the old API Key (not recommended):

```json
{
   "cloudflare": {
     "apiKey": "key",
     "email": "my@email.com",
   },
   "dnsZone": {
     "name": "domain.com",
     "record": "subdomain"
   }
 }
```

### Token Permissions
Currently, following Token permissions are required: 

- Permissions
    - Zone:Zone:Read
    - Zone:DNS:Edit
- Zone Resources
    - All Zones

Unfortunately, it's currently not possible to give the token only permissions on the desired Zone, this is a known
issue at Cloudflare, hopefully this will be fixed in future.

## Build from source
```shell script
make
```

## Running tests

```shell script
make test
```
