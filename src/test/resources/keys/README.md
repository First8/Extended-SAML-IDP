`public.key` and `private.key` were randomly generated using the following commands:

```
openssl genpkey -algorithm RSA -out private-non-pkcs8.key

openssl rsa -in private-non-pkcs8.key -pubout -outform DER -out public.key

openssl pkcs8 -topk8 -inform PEM -outform DER -in private-non-pkcs8.key -out private.key -nocrypt
```