# SigElf Documentation

## Generating keys

for the moment, sigelf doesn't support key generation, so we'll have to use openssl.\
**NOTE:** i show how to generate a self-signed certificate, but it is strongly recommended to make a CA in a real case.\
(technically your key will be a CA, so it can sign other certificates)

generation is a simple command:
```bash
openssl req \
    -x509   \
    -noenc  \
    -newkey rsa:2048    \
    -keyout ./sign.key  \
    -out ./sign.crt     \
    -subj '/CN=<your name>'
```

`-x509`: generate a certificate (rather than a certificate request, this is needed when using CAs)\
`-noenc`: no encryption (won't ask for a password when signing)\
`-newkey`: specify the algorithm/key length to use\
`-keyout`/`-out`: specify the output files\
`-subj`: specify the subject's info (you can check the [RFC4519](https://www.rfc-editor.org/rfc/rfc4519) to see the whole list of possible values)



## Signing

now that your `sign.key` and `sign.crt` are generated\
you have to move them to the sigelf's folder:
```sh
mkdir -p ~/.sigelf/
mv sign.key ~/.sigelf/default.key
chmod 600 ~/.sigelf/default.key # only readable/writable by you
mv sign.crt ~/.sigelf/default.crt
chmod 644 ~/.sigelf/default.crt # doesn't really matter who can read it
```

once this is done, you can finally use sigelf:\
(change sigelf by your sigelf's path)
```
~$ sigelf sign program.bin signed.bin
~$ sigelf lookup signed.bin
Signed By: <your name>
Issued By: <your name>
Trusted  : No
Status   : Unaltered
```

## Trusting keys

as you can see from the section above, sigelf doesn't trust you, which is why you'll have to add your key to the system.\
**NOTE:** for this you need root access.

```sh
# let's assume you're in root

# first of all, create sigelf config directory
mkdir /etc/sigelf/certs

# copy your certificate to the folder
cp /home/<USER>/.sigelf/default.crt /etc/sigelf/certs/

# we need to hash the certificates names so OpenSSL can find them.
openssl rehash /etc/sigelf/certs

# now we can change the owner and the permissions
chown -R root:root /etc/sigelf
chmod -R 644 /etc/sigelf
```

now if we lookup again:
```
~$ sigelf lookup signed.bin
Signed By: <your name>
Issued By: <your name>
Trusted  : Yes
Status   : Unaltered
```