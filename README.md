# cert-validator
X.509 certificate chain validator.

## Build
Clone this repository and run the following command in the toplevel directory:
```shell
go build .
```
## Usage
```shell
./cert-validator --input-csv=example/input-sample.csv --tls-root --root-ca-file=/etc/ssl/cert.pem --log-file=example/log.json -v 2
```
The ```--input-csv``` flag specifies the path to the input csv file.
The ```--tls-root``` flag specifies whether to use the CCADB TLS/SSL root CA certificates.
This flag is optional and defaults to ```false```.
Alternatively, you can specify ```--smime-root``` to use the CCADB S/MIME root CA certificates.
This flag is also optional and defaults to ```false```.
The ```--root-ca-file``` flag specifies the path to a root CA certificates file.
This flag is optional and defaults to empty.
The ```--log-file``` flag specifies the path to the log file.
It is optional and defaults to ```stdout```.
The ```-v``` flag controls the verbosity of the output.
It is optional and defaults to 0 and goes until 2.

If you do not specify ```--tls-root``` or ```--smime-root```, and/or ```--root-ca-file```, the program will use the system's root CA certificates only.
For all other cases, the system root CA certificates will be used in addition to the specified root CA certificates.

The ```--tls-root``` and ```--smime-root``` flags are mutually exclusive.
According to Mozilla, "an application that uses a root store for a purpose other than what the store was created for has a critical security vulnerability.
This is no different than failing to validate a certificate at all" [1].

[1] https://blog.mozilla.org/security/2021/05/10/beware-of-applications-misusing-root-stores/

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

The output is in parquet format and has the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- is_valid: boolean (nullable = true)
 |-- error: string (nullable = true)
```

The ```is_valid``` field is ```true``` if the chain is valid and ```false``` otherwise for the given PEM certificates.
The ```error``` field contains the error message if the chain is invalid and ```null``` otherwise.