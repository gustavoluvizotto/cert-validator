# cert-validator
X.509 certificate chain validator.

## Description
This program validates X.509 certificate chains using the ```crypto/x509``` Go package.
It can validate chains using different root stores such as the CCADB TLS/SSL and s/MIME root CA certificates [1], Microsoft root store **TODO**, Google services root store [2], Apple trust store [3], and optionally a custom root CA certificates file given by the user.
All the root stores are downloaded on the fly and used to validate the chains, so we always use the latest version of the root stores.
According to Mozilla, "an application that uses a root store for a purpose other than what the store was created for has a critical security vulnerability.
This is no different from failing to validate a certificate at all" [4].

[1] https://www.ccadb.org/resources   
[2] https://pki.goog/roots.pem  
[3] https://support.apple.com/en-us/HT213917  
[4] https://blog.mozilla.org/security/2021/05/10/beware-of-applications-misusing-root-stores/

## Environment
Currently, it works only on Linux.
That's because the program appends other root CAs to the system's root CA certificates, and the x509 package in Go does not support this on Windows and macOS.

## Requirements
* Go environment (1.21.1 or later).
* Internet connection (to download the CCADB, Microsoft, Google and Apple root CA certificates). 
* Podman (in case you want to use the container solution).
* Apple root certificates are stored in DACS object store and require valid credentials to access them.
Hence, one can skip by using ```--no-apple``` flag.
The only reason for this requirement is that the Apple root certificates (pem format) are not available online.
We obtain them from Apple Mac machine and store them in our research group data center.

The access to the ```credentials``` file must be granted by the owner of this repo.
The ```credentials``` file must be placed in the same folder of this project and has the following format:
```
[download]
aws_access_key_id = <>
aws_secret_access_key = <>
```

## Build
Clone this repository and run the following command in the toplevel directory:
```shell
go build .
```

## Usage
```shell
./cert-validator --input-csv=example/input-sample.csv --root-ca-file=certs.pem --scan-date=20230920  -v 2 --log-file=example/log.json --output=example/output-sample.parquet --rm
```
The ```--input-csv``` flag specifies the path to the input csv file.
Alternatively, the user can specify the input in parquet format using the ```--input-parquet``` flag.
These flags are mutually exclusive.
The ```--root-ca-file``` flag specifies the path to a custom root certificate(s) file.
This flag is optional and defaults to empty.
The ```--scan-date``` flag specifies the date the certificates were collected which is used to determine the validity of the certificates.
The ```-v``` flag controls the verbosity of the output.
It is optional and defaults to 0 and goes until 2.
The ```--log-file``` flag specifies the path to the log file.
It is optional and defaults to ```stdout```.
The ```--output``` flag specifies the path to the output parquet file.
The user can also specify the flag ```--no-apple``` to skip downloading the Apple root certificates from our research group data center (requires special credentials).
The ```--rm``` flag specifies whether to remove temporary files (downloaded root certificates) after the program finishes.
It is optional and defaults to ```false```.

## Container Usage
If you want to run the program in a container, you can build the container image by running the following command in the toplevel directory:
```shell
./build.sh
```

Then you must run the container by executing the following command:
```shell
./run.sh --input-csv=shared_dir/input-sample.csv ...(same parameters as the ones described in the [Usage](#usage) section)
```

Note that all your input and output files must be in the ```shared_dir``` directory.

## Input and Output
There are 2 different input types the program accepts: csv and parquet.

The input in parquet format and has the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- chain: array (nullable = false)
 |    |-- element: string (containsNull = false)
```
Where ```chain``` is an array of PEM-encoded X.509 certificates containing the leaf certificate and its intermediate certificates up to the root certificate collected from a TLS connection state.

The input in csv format has the following columns:
```
id,chain
```
Where ```chain``` is a comma-separated list of PEM-encoded X.509 certificates within double quotes.
The first element of the ```chain``` is considered the leaf certificate, and we assume that the chain is already in signing order (leaf certificate to the root certificate).
The ```id``` parameters in both types of input is an integer that uniquely identifies the chain.

The output is in parquet format and has the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- generic_error: string (nullable = true)
 |-- root_stores: map (nullable = true)
 |    |-- key: string
 |    |-- value: struct (valueContainsNull = true)
 |    |    |-- root_store_error: string (nullable = true)
 |    |    |-- is_valid: boolean (nullable = true)
 |    |    |-- valid_chains: string (nullable = true)
```

The ```id``` field is the same as the one in the input.
The ```generic_error``` field contains the error message when the tool cannot even start to validate the chain, ```null``` otherwise.
The ```root_stores``` field contains a map of root stores to the results of the validation.
The ```key``` field contains the name of the root store and the ```value``` field contains the results of the validation itself.
The ```root_store_error``` field contains the error message if the chain is invalid and ```null``` otherwise.
The ```is_valid``` field is ```true``` if the chain is valid and ```false``` otherwise for the given PEM certificates.
The ```valid_chains``` field contains a comma-separated list of valid chains for the given PEM certificates if the chain is valid and ```""``` (empty) otherwise.
This is a string representation of a list of list of certificates fingerprints (SHA256 sum) that are valid and obtained from the output of the ```x509.Verify``` from ```crypto/x509``` Go package.

### Output validation
The ```crypto/x509``` Go package ```x509.Verify``` function build valid chains from the leaf to the root certificate using intermediate certificates provided in the input chain.
It does by recursively find potential parents of a certificate from a pool of candidates, root certificates first and then if not found, intermediate certificates.
From the pool of candidates, you can have multiple valid chains (e.g. cross signed certificates).
The ```x509.Verify``` algorithm acts as a depth-first search algorithm in its search for valid chains. 
