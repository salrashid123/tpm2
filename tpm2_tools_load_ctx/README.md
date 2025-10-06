
### TPM2 saved context compatibility with go-tpm 

this is just an experimental example of trying to load a key context saved by `tpm2_tools` into go-tpm.

THe following will use tpm2_tools to create a key and save it to `key.ctx`

then the go program will load it using by parsing out `key.ctx` values 

it tries to address [https://github.com/google/go-tpm/issues/378](https://github.com/google/go-tpm/issues/378)

This sample also demonstrates a path where you can load a key in go-tpm, save it as a context file that is compatible with tpm2_tools

THe follwoing converts

* `tpm2_tools` saved context --> `go-tpm`  load context
   i.,e you create a key with tpm2_tools, save it and then read with go-tpm

* `go-tpm` key --> `tpm2_tools` context
   i.,e you create a key with go-tpm, save it and then read with tpm2_tools


>> WARNING, i don't know how robust this is...i made some assumptions on what some of the structures are actually used for

### Setup

I'll use a swtpm to create a key

```bash
# rm -rf myvtpm && mkdir myvtpm  && \
# swtpm_setup --tpmstate myvtpm --tpm2 --create-ek-cert && \
   swtpm socket --tpmstate dir=myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear

export TPM2TOOLS_TCTI="swtpm:port=2321"

tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c key.ctx
tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o key.pem 
tpm2_flushcontext -t && tpm2_flushcontext -s && tpm2_flushcontext -l
```

#### TPM2_TOOLS --> GO-TPM


the follwoing will read a tpm2 generated key file `key.ctx`, parse it and load it for use with go-tpm.

From there it will use the key to encrypt some data

```bash
go run from_tpm2_tools/main.go


header:  badcc0de
version:  1
Hierarchy: 40000001
SavedHandle: 80000000
Sequence: 2
context+metadata: 0000000001800040112315c7b03d188040c4f4c550072c62547e5dfbf9ef83ccbaa59c40ce39a175b1d4dd0db1c034041401d3e8a6144f9fc720b4569b9bdeca5c47921d213608658931209745c4e7a610e3d65b8298056c6e251b7f357b0eaaf6505b64d6b8b0271979222e7b00f66bb55c9d1f6b075826bcd20d6da3c25d16280bda5bd74da4d83f9ade38f0e59cc1194e449a9a9349b8e195131c344adf57316c283ca6db9542a7222486a62e6c86a7b8306b9586faadae8518d0bda91ef4dfe04c797dee22e82350cf9fce1527ea2df47fd815e719e16c46fae353783347ade5753b2d77bdb4809a2f839de6a40f8263c5ec6df3447752fcc2217734dc02590ce40a93323d26ffba614662111591efa338c449cdb2f552f70014bde332f06f1511cec75d7e335078802377d7d775f486089e154a61ca4b86afb3c137e09d1706637392401ec5eb4252d130e974f235e1ee4b2089ec997c343ab12895e731e469957d08637e0cabb919311ced2cc98f6dd72ffaaa214de944d0357e44176657daeb2ef2d70000800000010022000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e6770000000100320025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
Size of context: 384
context: 0040112315c7b03d188040c4f4c550072c62547e5dfbf9ef83ccbaa59c40ce39a175b1d4dd0db1c034041401d3e8a6144f9fc720b4569b9bdeca5c47921d213608658931209745c4e7a610e3d65b8298056c6e251b7f357b0eaaf6505b64d6b8b0271979222e7b00f66bb55c9d1f6b075826bcd20d6da3c25d16280bda5bd74da4d83f9ade38f0e59cc1194e449a9a9349b8e195131c344adf57316c283ca6db9542a7222486a62e6c86a7b8306b9586faadae8518d0bda91ef4dfe04c797dee22e82350cf9fce1527ea2df47fd815e719e16c46fae353783347ade5753b2d77bdb4809a2f839de6a40f8263c5ec6df3447752fcc2217734dc02590ce40a93323d26ffba614662111591efa338c449cdb2f552f70014bde332f06f1511cec75d7e335078802377d7d775f486089e154a61ca4b86afb3c137e09d1706637392401ec5eb4252d130e974f235e1ee4b2089ec997c343ab12895e731e469957d08637e0cabb919311ced2cc98f6dd72ffaaa214de944d0357e44176657daeb2ef2d7
     oprand: 0
     handle 80000001
     name: 000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e677
     selector: 00000001
     public: 00320025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
Recalled Name 000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e677
IV: c8a34349fa87a79ec80a9a2b14d4de89
Encrypted f040a79e45
Decrypted foooo
```

#### GO-TPM --> TPM2_TOOLS

THe following wiill read a PEM encoded key file into go-tpm (you can load a key in any other way you want).

Once the key is loaded, it will populate the structures and save it as `output.ctx` which is then usableby tpm2_tools

```bash
go run to_tpm2_tools/main.go

$ go run to_tpm2_tools/main.go 
Hierarchy: 40000001
SavedHandle 80000000
Sequence: 87
ContextBLob Length: 384
ContextBLob: 0040611191b553cecce4819ec22744c3f2f9458c5b4eb5427feb83860c20d2dbb40f2393b8689836cff2afe05e4a34cb4590670d773b76892da3620a685e68ff3616f2b27ebd1c4d270181f0bfb566886ed7149f7fbadb5b143b4ddba5522e5355f1bfa722fef5e5aa1323222adcf7a80d2a06a5b310223c977523b530a26c312f1be1f1b3e1091ac68c30bed323f023697b98621db39e60c628b2a8b12ccbcac4813716acef2f7e89993e1106f28c585ffb4008da83f6690907324c210663cbe31eaa041a70842876fa4f73601846042b6c25d9911b3c8653732cd25b178ebab066ce6a1fdddf5bcf7f99b132c12361a4016924b5464374c1501cd77ceed474eac75c8f0de7a1130c0c84ee21a0fb7957c6739f2d1b847b5a4d2e058042facebd4f2800d661e2290ee4d132a6644897a99f6c4f305f3f26bccca552292f88763d45925d5039d1bd874ca9af939a656a6a9c2a148c2c8eed6a77f8c3d2a323b4b8947772e11af4b2751ca9c3aaf0c114418c5f506d99bbc8772ec855466d4cab
Name: 000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e677
Public : 0025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
final bytes to write    badcc0de000000014000000180000000000000000000005701e80000000001800040611191b553cecce4819ec22744c3f2f9458c5b4eb5427feb83860c20d2dbb40f2393b8689836cff2afe05e4a34cb4590670d773b76892da3620a685e68ff3616f2b27ebd1c4d270181f0bfb566886ed7149f7fbadb5b143b4ddba5522e5355f1bfa722fef5e5aa1323222adcf7a80d2a06a5b310223c977523b530a26c312f1be1f1b3e1091ac68c30bed323f023697b98621db39e60c628b2a8b12ccbcac4813716acef2f7e89993e1106f28c585ffb4008da83f6690907324c210663cbe31eaa041a70842876fa4f73601846042b6c25d9911b3c8653732cd25b178ebab066ce6a1fdddf5bcf7f99b132c12361a4016924b5464374c1501cd77ceed474eac75c8f0de7a1130c0c84ee21a0fb7957c6739f2d1b847b5a4d2e058042facebd4f2800d661e2290ee4d132a6644897a99f6c4f305f3f26bccca552292f88763d45925d5039d1bd874ca9af939a656a6a9c2a148c2c8eed6a77f8c3d2a323b4b8947772e11af4b2751ca9c3aaf0c114418c5f506d99bbc8772ec855466d4cab0000800000010022000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e6770000000100320025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
```

Then encrpt/decrypt with both key context

```bash
### encrypt with tpm2_tools genreated key
tpm2_encryptdecrypt -Q --iv iv.bin -c key.ctx -d -o decrypt.out encrypt.out

## decrypt with go-tpm generated key
tpm2_encryptdecrypt -Q --iv iv.bin -c output.ctx -d -o decrypt.out encrypt.out

```
In my case the key name had the following specs.

```bash
$ tpm2_readpublic -c key.ctx
name: 000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e677
qualified name: 000b0fa5d29fe52b2472f27c5cb62ffd05e49232908cc04019eecfbff4c36f24c034
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign
  raw: 0x60072
type:
  value: symcipher
  raw: 0x25
sym-alg:
  value: aes
  raw: 0x6
sym-mode:
  value: null
  raw: 0x10
sym-keybits: 128
symcipher: dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9

$ tpm2_print -t TPM2B_PUBLIC key.pub
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign
  raw: 0x60072
type:
  value: symcipher
  raw: 0x25
sym-alg:
  value: aes
  raw: 0x6
sym-mode:
  value: null
  raw: 0x10
sym-keybits: 128
symcipher: dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
```

And notice the tpm and go generated keys are of the same size
```bash
$ tpm2_print -t TPMS_CONTEXT key.ctx
version: 1
hierarchy: owner
handle: 0x80000000 (2147483648)
sequence: 2
contextBlob: 
	size: 488

$ tpm2_print -t TPMS_CONTEXT output.ctx 
version: 1
hierarchy: owner
handle: 0x80000000 (2147483648)
sequence: 85
contextBlob: 
	size: 488

```

---

### ParsingTPM2_TOOLS saved context

The context file tpm2_tools uses basically uses this structure

```c
    /*
     * Saving the TPMS_CONTEXT structure to disk, format:
     * TPM2.0-TOOLS HEADER
     * U32 hierarchy
     * U32 savedHandle
     * U64 sequence
     * U16 contextBlobLength
     * BYTE[] contextBlob
     */
```

Critically, contextBlob is not what go-tpm uses in plain `tpm2.ContextSave` but a complex structure which includes the raw context info from go-tpm plus values for `Esys_ContextSave` described below

see the section below for links to tpm2_tools and `ESYS_Context`

* [tpm2_tools/file.c](https://github.com/tpm2-software/tpm2-tools/blob/c2d1ee7c60dbcc24c4251eb1a99138d2d29fad73/lib/files.c#L244)
* [ESYS contextSave](https://trustedcomputinggroup.org/wp-content/uploads/TSS_TSS-2.0-Enhanced-System-API_V0.9_R03_Public-Review-1.pdf)


For a specific run of the parsing, consider the tpm2_tools generated context here

```bash
$ xxd -p -c 100000 key.ctx 
badcc0de000000014000000180000000000000000000000201e80000000001800040112315c7b03d188040c4f4c550072c62547e5dfbf9ef83ccbaa59c40ce39a175b1d4dd0db1c034041401d3e8a6144f9fc720b4569b9bdeca5c47921d213608658931209745c4e7a610e3d65b8298056c6e251b7f357b0eaaf6505b64d6b8b0271979222e7b00f66bb55c9d1f6b075826bcd20d6da3c25d16280bda5bd74da4d83f9ade38f0e59cc1194e449a9a9349b8e195131c344adf57316c283ca6db9542a7222486a62e6c86a7b8306b9586faadae8518d0bda91ef4dfe04c797dee22e82350cf9fce1527ea2df47fd815e719e16c46fae353783347ade5753b2d77bdb4809a2f839de6a40f8263c5ec6df3447752fcc2217734dc02590ce40a93323d26ffba614662111591efa338c449cdb2f552f70014bde332f06f1511cec75d7e335078802377d7d775f486089e154a61ca4b86afb3c137e09d1706637392401ec5eb4252d130e974f235e1ee4b2089ec997c343ab12895e731e469957d08637e0cabb919311ced2cc98f6dd72ffaaa214de944d0357e44176657daeb2ef2d70000800000010022000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e6770000000100320025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
```

which you can breadk down as:


```
* magic: `badcc0de`   // static const UINT32 MAGIC = 0xBADCC0DE;
* version: `00000001`   // #define CONTEXT_VERSION 1
* hierarch: `40000001`
* savedHandle `80000000`  
* sequence `0000000000000002`
* length (contextblob+metadata)   `01e8`  length 488
* context blob + metadata:
    context struct
      0000  // always 0
      00000180 // size 384
      0040112315c7b03d188040c4f4c550072c62547e5dfbf9ef83ccbaa59c40ce39a175b1d4dd0db1c034041401d3e8a6144f9fc720b4569b9bdeca5c47921d213608658931209745c4e7a610e3d65b8298056c6e251b7f357b0eaaf6505b64d6b8b0271979222e7b00f66bb55c9d1f6b075826bcd20d6da3c25d16280bda5bd74da4d83f9ade38f0e59cc1194e449a9a9349b8e195131c344adf57316c283ca6db9542a7222486a62e6c86a7b8306b9586faadae8518d0bda91ef4dfe04c797dee22e82350cf9fce1527ea2df47fd815e719e16c46fae353783347ade5753b2d77bdb4809a2f839de6a40f8263c5ec6df3447752fcc2217734dc02590ce40a93323d26ffba614662111591efa338c449cdb2f552f70014bde332f06f1511cec75d7e335078802377d7d775f486089e154a61ca4b86afb3c137e09d1706637392401ec5eb4252d130e974f235e1ee4b2089ec997c343ab12895e731e469957d08637e0cabb919311ced2cc98f6dd72ffaaa214de944d0357e44176657daeb2ef2d7  // contextblob of size 384

    metadata

      0000 /**< size of the operand buffer */
      80000001 /**< Handle used by TPM */
      0022  // length = 34
      000b03f4e82d95cc2f50f3afda79980356ca8ca9b83d47231c15d7571b4669f9e677 /**< TPM name of the object */
      00000001        /**< Selector for resource type */  #define IESYSC_KEY_RSRC                1    /**< Tag for key resource */'
      0032  // len public
      0025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9  // public tpm2b

```

note the public key:

```bash
$ xxd -p -c 1000 key.pub 

00320025000b0006007200000006008000100020dc24075e84cea2fbc7d5302b3719aff39412a4051cb55c44a69bacb03993cae9
```


---


#### ESYS Context

* [ESYS contextSave](https://trustedcomputinggroup.org/wp-content/uploads/TSS_TSS-2.0-Enhanced-System-API_V0.9_R03_Public-Review-1.pdf)
* [Esys_contextSave.c](https://github.com/tpm2-software/tpm2-tss/blob/master/src/tss2-esys/api/Esys_ContextSave.c#L266)

```
10.13 Esys_ContextSave Commands

If the ESYS_TR object being saved refers to a session, the ESYS_TR object is invalidated.
This means that the ESYS_TR object cannot be used for any future operations and the variable can be
discarded.

Futhermore, the ESAPI implementation augments the data inside the saved context blob by the metadata
it requires for e.g. object names, if needed. This is done by augmenting the contents of context-
>contextBlob.buffer (and size). This data is used to restore the ESYS_TR object during ContextLoad.
NOTE: authorization values kept inside the ESYS_TR object metadata shall not be stored in the context
blobs.

The recommended implementation is:

typedef TPM2B_EVENT TSS2B_METADATA;
typedef struct {
 UINT32 reserved; /* Must always be zero */
 TPM2B_CONTEXT_DATA tpmContext;
 TPM2B_METADATA esysMetadata;
} ESYS_CONTEXT_DATA;
if (e.g. type == RSA_KEY && type != HashSequence) {
 ESYS_CONTEXT_DATA esyscontextData;
 esyscontextData.reserved = 0;
 esyscontextData.tpmContext.buffer = context->contextBlob.buffer;
 esyscontextData.tpmContext.size = context->contextBlob.size;
 esyscontextData.esysMetadata.buffer = metadata;
 esyscontextData.esysMetadata.size = metadata_size;
 context->contextBlob.buffer = esyscontextData;
 context->contextBlob.size = sizeof(UINT32) +
 sizeof(UINT16) + esyscontextData.tpmContext.size +
 sizeof(UINT16) + esyscontextData.esysMetadata.size;
}
```

in tpm2_tools

```c
/**  Esys resource with size field
 */
typedef struct {
    UINT16                                         size;    /**< size of the operand buffer */
    IESYS_RESOURCE                                 data;    /**< Esys resource data */

} IESYS_METADATA;


/** Type for representing TPM-Resource
 */
typedef struct {
    TPM2_HANDLE                                  handle;    /**< Handle used by TPM */
    TPM2B_NAME                                     name;    /**< TPM name of the object */
    IESYSC_RESOURCE_TYPE                       rsrcType;    /**< Selector for resource type */
    IESYS_RSRC_UNION                               misc;    /**< Resource specific information */
} IESYS_RESOURCE;

#define IESYSC_KEY_RSRC                1    /**< Tag for key resource */'
```




