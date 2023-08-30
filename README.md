# cert-validator
X.509 certificate chain [validator](validator)

The input have the following schema:
```
root
 |-- id: integer (nullable = true)
 |-- chain: array (nullable = false)
 |    |-- element: string (containsNull = false)
```
Where the chain is an array of PEM encoded X.509 certificates.

