# SChat (Duo)

Secure TLS/SSL Windows E2E Chat.  
Currently just supporting TLS 1.2 due to Windows SChannel restrictions.

## Version ##
1.0.5  
Last changed: 20.11.2021

## Descrtiption
GUI chat application that connects two communication partners directly over TCP using TLS/SSL to secure the communication.
The GUI is very *basic* at the moment but is work in progress.

## Usage
One user plays the server and the other user has to connect to that server.  
Both sides need a valid certificate stored in the local user cert store.
On Windows 10, the maximum possible security is TLS 1.2 with a RSA certificate. 
The Length can be of 8192 bit or even 16384 bit. 
16384 RSA might trigger network anomaly detection. 
The edward curve and/or TLS 1.3 is not available for usage on Windows 10 OS.

## Requirements
- msbuild tools

## Build

### Windows msbuild in developer cmd
**easy**
```bash
$devcmd> build.bat [/g] [/d] [/r] [/dp] [/dphd] [/dpm] [/pdb]
```
Targets:
- /g: Build the complete gui program.
Build modes:
- /d: Build in debug mode.
- /r: Build in release mode.
- /b: Bitness of exe. 32^|64. Default: 64.
- /rtl: Build with runtime libs.
- /pdb: Compile with pdbs.
Flags:
- /dp: Debug print output.
- /dphd: Extended hex dump debug print output.
- /dpm: Messages are logged in the log file.
Other:
- /h: Print this.


**wordy**
```bash
$devcmd> msbuild [server.vcxproj|client.vcxproj] [/p:Platform=x86|x64] [/p:Configuration=Debug|Release] [/p:RunTimeLib=Debug|Release] [/p:DebugPrint=(1|2|4)] [/p:PDB=0|1]
```
Options:
 - RunTimeLib: Statically include CRT debug or release runtime library.
 - DebugPrint: Show debug print for `1`, extendend hex dumps for `2` and message dump for `4`. Theses are flags and may be combined by `or` or `+`.
 - PDB: Generate PDB files for `1`.

## Run
`SChat.exe` may be run by double clicking or via the cmd.
Start options may be passed via the command line or a config file.
The config file is searched for in the current directory (out of which the application is started) and has to be named `.config`.

**Usage:**
```bash
$ SChat.exe [/i ip] [/v vs] [/p port] [/n name] [/c certThumb] [/l logDir] [/d certDir] [/f fileDir]
```
**Options:**
 - /i string : The ip string.
 - /v int: The ip version 4 or 6 (default). Just needed, if ip is empty.
 - /p uint16 : The listening port number of the server.
 - /n string : The nick name.
 - /c string : Thumbprint of the cert in the local user cert store.
 - /l string : Directory to store the log files in. Defaults to current dir.
 - /d string : Directory to store the cert files in. Defaults to current dir.
 - /f string : Directory to store transfered files. Defaults to current dir.
 
**Example:**
```bash
$ server SChat.exe -i 123.456.789.876 -p 5432 -n alice -c aliceCertThumbPrint
```

Most options may be skipped, because there are input fields in the app for them too.
Currently, the options `/l`, `/d` and `/f` are not possible to be set in the app.

After starting, one partner has to play the server side.
`User name`, `Port` and `Cert thumb` (thumbprint of the certificate) have to be filled with valid values.
Ip may be filled to make the server listen to only that IP.
If not filled, `Version` has to be set to `4` or `6`.
Then the `Listen` button has to be pressed.

The client side has to fill `User name`, `Ip`, `Port` and `Cert thumb` (thumbprint of the certificate) with valid values and then press the `Connect` button.
`Version` may be left empty.

After that, the communication partners may send messages to each other by typing into the `Message` input and pressing `Enter` or the `Send` button.

There is a log file beeing created, named `<server|client>-<date>-<time>.log` in the current working directory, which will be filled with infos, depending on the debug print compiler flags.
By passing the command line option `/l` the directory where the files are saved may be changed.

The certificate of the other side is stored in `<sha256(cert)>.der` in the current working directory (default).
The hash (sha256) of the certificate is also displayed with the connection info in the message output.
This should by verified by calculating and comparing the hash with the comunication partner or sharing it in advance.
By passing the command line option `/d` the directory where the certificates are saved may be changed.

An example .config is located in [res/.config.example](res/.config.example).

The logs are not readable while the app is running. 
This may be fixed in the future.



## Create certificate
An easy way to create a certificate on Windows is to use Power Shell [New-SelfSignedCertificate][1]:

```bash
ps> New-SelfSignedCertificate -DnsName <name> -CertStoreLocation "Cert:\CurrentUser\My\" -KeyAlgorithm RSA -KeyLength 8192 -HashAlgorithm SHA256
ps> New-SelfSignedCertificate -DnsName <name> -CertStoreLocation "Cert:\CurrentUser\My\" -KeyAlgorithm RSA -KeyLength (2048|4096|8192|16384) -HashAlgorithm (SHA256|SHA384|SHA512)
[ps> New-SelfSignedCertificate -DnsName <name> -CertStoreLocation "Cert:\CurrentUser\My\" -KeyAlgorithm RSA_curve25519 -CurveExport CurveName] // doesn't work
ps> New-SelfSignedCertificate -DnsName <name> -CertStoreLocation "Cert:\CurrentUser\My\" -KeyAlgorithm RSA_brainpoolP(256|384|512)r1 -CurveExport CurveName
ps> New-SelfSignedCertificate -DnsName <name> -CertStoreLocation "Cert:\CurrentUser\My\" -KeyAlgorithm ECDSA_nistP(256|384|521) -CurveExport CurveName
```
DnsName may be any name and fills out `CN` and `Subject alternative name`.  
For more options call help:
```bash
ps> New-SelfSignedCertificate -?
```

Valid curve names may be found with 
```bash
$ certutil -displayEccCurve 
```
Just entries with a `Curve OID` are valid. 
That's why `RSA_curve25519` does not work (by default).

Another way is to generate a full .pfx certificate with `openssl` and import it into the local user store.
(But importing an openssl ed25519 curve certificate does not work either.)

[1]: https://docs.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2019-ps

## List certificates in store with thumbprints
```bash
ps> Get-ChildItem "Cert:\CurrentUser\My"
```

## Open certificate store
```bash
$ mmc
```
`File > Add/Remove Snap-in`, choose `Certificates` and the `Add > `My user account`, `finish`, `Ok`.
Click on `Certificates - Current User > Personal > Certificates`.


## Questions, issues, bugs, security flaws, feature requests
Feel free to open an issue.


## COPYRIGHT, CREDITS & CONTACT
### License
Published under [GNU GENERAL PUBLIC LICENSE](LICENSE).   

### Author
- Henning Braun ([henning.braun@fkie.fraunhofer.de](henning.braun@fkie.fraunhofer.de)) 
