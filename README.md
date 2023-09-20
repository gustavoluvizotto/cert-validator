# cert-validator
X.509 certificate chain validator.

## Build
Clone this repository and run the following command in the toplevel directory:
```shell
go build .
```
## Usage
```shell
./cert-validator --input-parquet=example/input-sample.parquet -v 2 --log-file=example/log.json
```
The ```-v``` flag controls the verbosity of the output.
It is optional and defaults to 0.
The ```--log-file``` flag specifies the path to the log file.
It is optional and defaults to ```stdout```.

## Input and Output
The input is in parquet format and has the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- chain: array (nullable = false)
 |    |-- element: string (containsNull = false)
```
Where ```chain``` is an array of PEM-encoded X.509 certificates.

The output is in parquet format and has the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- chain: array (nullable = true)
 |    |-- element: string (containsNull = true)
 |-- is_valid: boolean (nullable = true)
```

The ```is_valid``` field is ```true``` if the chain is valid and ```false``` otherwise for the given PEM certificates.
