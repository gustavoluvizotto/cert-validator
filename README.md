# cert-validator
X.509 certificate chain validator.

## Environment
Currently, it works only on Linux.
That's because the program appends other root CAs to the system's root CA certificates, and the the x509 package in Go does not support this on Windows and macOS. 

## Requirements
* Go environment
* Internet connection (to download the CCADB root CA certificates). 
This can be avoided by **not** specifying the ```--tls-root``` or ```--smime-root``` flags.
* Podman (in case you want to use the container solution).

## Build
Clone this repository and run the following command in the toplevel directory:
```shell
go build .
```

## Usage
```shell
./cert-validator --input-csv=example/input-sample.csv --tls-root --root-ca-file=/etc/ssl/cert.pem --scan-date=20230920  -v 2 --log-file=example/log.json --output=example/output-sample.parquet
```
The ```--input-csv``` flag specifies the path to the input csv file.
The ```--tls-root``` flag specifies whether to use the CCADB TLS/SSL root CA certificates.
This flag is optional and defaults to ```false```.
Alternatively, you can specify ```--smime-root``` to use the CCADB S/MIME root CA certificates.
This flag is also optional and defaults to ```false```.
The ```--root-ca-file``` flag specifies the path to a root CA certificates file.
This flag is optional and defaults to empty.
The ```--scan-date``` flag specifies the date the certificates were collected which is used to determine the validity of the certificates.
The ```-v``` flag controls the verbosity of the output.
It is optional and defaults to 0 and goes until 2.
The ```--log-file``` flag specifies the path to the log file.
It is optional and defaults to ```stdout```.
The ```--output``` flag specifies the path to the output parquet file.

If you do not specify ```--tls-root``` or ```--smime-root```, and/or ```--root-ca-file```, the program will use the system's root CA certificates only.
For all other cases, the system root CA certificates will be used in addition to the specified root CA certificates.

The ```--tls-root``` and ```--smime-root``` flags are mutually exclusive.
According to Mozilla, "an application that uses a root store for a purpose other than what the store was created for has a critical security vulnerability.
This is no different than failing to validate a certificate at all" [1].

[1] https://blog.mozilla.org/security/2021/05/10/beware-of-applications-misusing-root-stores/

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
Where ```chain``` is an array of PEM-encoded X.509 certificates.

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
 |-- is_valid: boolean (nullable = true)
 |-- error: string (nullable = true)
 |-- valid_chains: string (nullable = true)
```

The ```id``` field is the same as the one in the input.
The ```is_valid``` field is ```true``` if the chain is valid and ```false``` otherwise for the given PEM certificates.
The ```error``` field contains the error message if the chain is invalid and ```null``` otherwise.
The ```valid_chains``` field contains a comma-separated list of valid chains for the given PEM certificates if the chain is valid and ```[]``` otherwise.
This is a string representation of a list of list of indexes of the certificates in the input chain.
E.g. "[[0, 2, 1], [0, 1, 2]]" means that two chains are valid: the first chain the leaf certificate is take from the index 0 of the input chain, the intermediate certificates are indexes 2 and 1.
The second chain the leaf certificate is taken from the index 0 of the input chain, the intermediate certificates are indexes 1 and 2.

## Notes
The program tries to find at most ```maxPermutations=250000``` (see ```validator/validator.go```) other valid chains.
It is a trade-off between depth of the search and the time it takes to find the valid chains.