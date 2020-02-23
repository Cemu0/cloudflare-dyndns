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
