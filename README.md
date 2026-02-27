# PKI Copy and Paste (PCP)

The `pcp-rs` utility can be used to clone PKI artifacts such that all fields are held constant except for algorithm
fields and signature fields. It was initially written to clone the 
[PKITS test data](https://csrc.nist.gov/projects/pki-testing) from NIST using ML-DSA variants.

The tool makes two passes over a set of certificates. On the first pass, it records each `SubjectKeyIdentifier` value
and generates a fresh key pair per the [GenerationSettings]. On the second pass, it updates algorithm, 
`SubjectPublicKeyInfo`, and signature fields using freshly generated key material associated with the subject and 
issuer.

The goal is to enable testing new algorithms in the context of arbitrarily complex certification paths.

Much of the code that comprises `pcp-rs` was poached from [kemri_toy](https://github.com/carl-wallace/kemri_toy).

## Usage
```bash
$ ./target/release/pcp-rs 

Usage: pcp-rs [OPTIONS] --certs-folder <CERTS_FOLDER>

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Logging:
  -c, --log-to-console
          Log output to the console
  -l, --logging-config <LOGGING_CONFIG>
          Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See https://docs.rs/log4rs/latest/log4rs/ for details

Source Artifacts:
  -x, --certs-folder <CERTS_FOLDER>
          Full path and name of the folder containing certificate artifacts. The folder will be recursively traversed in search of target file extensions
  -r, --crls-folder <CRLS_FOLDER>
          Full path and name of the folder containing CRL artifacts. The folder will be recursively traversed in search of target file extensions
  -f, --file-extensions <FILE_EXTENSIONS>
          Semi-colon delimited list of file extensions to ingest from the `certs-folder` [default: .der;.crt;.cer;.pem]

Generated Artifacts:
  -g, --generation-settings <GENERATION_SETTINGS>
          Full path and filename of the file containing JSON-formatted settings that govern preparation of generated artifacts
  -s, --storage-settings <STORAGE_SETTINGS>
          Full path and filename of the file containing JSON-formatted settings that govern storage of generated artifacts
```

When `pcp-rs` is used to generate updated PKITS artifacts, manual steps are required to address some negative test cases,
i.e., artifacts that support testing invalid signatures.

The following sections describe generating PKITS clones using ML-DSA-44, ML-DSA-65, and ML-DSA-87. The `pkits.sh` file 
uses provided settings files to generate clones in the `./target` folder.

### Cloning RSA artifacts using ML-DSA-44

By default, `pcp-rs` will generate fake certificates based on certificates from `certs-folder` with `RSA_ENCRYPTION` keys 
replaced by `ID_ML_DSA_44` keys and freshly generated artifacts stored in `./storage` using a folder hierarchy similar to 
the structure of the `PKITS_Data` folder. Following invocation of the command shown below, a folder named `storage` will
be created in the current working directory and contain `certs`, `crls`, `pkcs12` and `keys` folders. The `keys` folder
contains intermediate values generated during the cloning process.

To change the storage location, a settings file like the following can be used.

```json
{
"folder": "./target/pkits_ml_dsa_44"
}
```


```bash
pcp-rs -c -x /Users/username/Desktop/PKITS_data/certs -r /Users/username/Desktop/PKITS_data/crls/ -s ss_44.json
```
### Cloning RSA artifacts using ML-DSA-65

The `--generation-settings` and `--storage-settings` can be used to tailor generation and behavior. At present, 
[StorageSettings] simply consist of a file folder.

```json
{
"folder": "./target/pkits_ml_dsa_65"
}
```
[GenerationSettings] can define algorithm mappings (though only a single mapping has been tested to date).

```json
{
	"alg_mappings" : [
		{
		"source_alg": "1.2.840.113549.1.1.1",
		"target_alg": "2.16.840.1.101.3.4.3.18"
		}
	]
}
```

Assuming the settings shown above are available in the indicated files, i.e., `ss_65.json` and `gen_65.json`, the following command can be used to generate 
an updated PKITS data set using `ML-DSA-65`

```bash
pcp-rs -c -x /Users/username/Desktop/PKITS_data/certs -r /Users/username/Desktop/PKITS_data/crls/ -s /Users/username/Desktop/ss_65.json -g /Users/username/Desktop/gen_65.json 
```
### Cloning RSA artifacts using ML-DSA-65

Similar to the previous section, using the settings and command shown below can generate a PKITS data set using `ML-DSA-87.`

```json
{
"folder": "./target/pkits_ml_dsa_87"
}
```
```json
{
	"alg_mappings" : [
		{
		"source_alg": "1.2.840.113549.1.1.1",
		"target_alg": "2.16.840.1.101.3.4.3.19"
		}
	]
}
```
```bash
pcp-rs -c -x /Users/username/Desktop/PKITS_data/certs -r /Users/username/Desktop/PKITS_data/crls/ -s /Users/username/Desktop/ss_87.json -g /Users/username/Desktop/gen_87.json 
```

## Potential TODO items
- implement use of the `--file-extensions`, which is currently not used
- save various forms of private key to the `keys` folder, i.e., seed-only, expanded-only, both 
- add support for generating SLH-DSA artifacts and composite ML-DSA artifacts
- add support for generating end entity certificates with ML-KEM keys
- add support for cloning artifacts without changing the algorithm
- add support for generating artifacts for the `smime` folder
- add support for cloning artifacts by generating certificate requests with same contents but new keys
- implement richer algorithm mapping, i.e., key sizes, key usage, maybe based on namespaces, etc.
