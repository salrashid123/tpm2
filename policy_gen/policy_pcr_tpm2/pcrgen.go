package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

/*

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm
sudo swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert
sudo swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5


## new window

export TPM2TOOLS_TCTI="swtpm:port=2321"
export TPM2OPENSSL_TCTI="swtpm:port=2321"
export TPM2TSSENGINE_TCTI="swtpm:port=2321"
export OPENSSL_MODULES=/usr/lib/x86_64-linux-gnu/ossl-modules/

tpm2_pcrextend 23:sha256=0x0000000000000000000000000000000000000000000000000000000000000000
tpm2_pcrread sha256:23

echo "foo" > secret.dat
openssl rand  -out iv.bin 16


tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
tpm2_pcrread sha256:23 -o pcr23_val.bin
tpm2_startauthsession -S session.dat
tpm2_policypcr -S session.dat -l sha256:23  -L policy.dat -f pcr23_val.bin
tpm2_flushcontext session.dat


printf '\x00\x00' > unique.dat
tpm2_createprimary -C o -G ecc  -g sha256  -c primary.ctx -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" -u unique.dat

tpm2_create -g sha256 -G aes -u key.pub -r key.priv -C primary.ctx -L policy.dat
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l
tpm2_load -C primary.ctx -u key.pub -r key.priv -n key.name -c aes.ctx


tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23"  -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -o cipher.out -p"session:session.dat"  secret.dat
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l

tpm2_startauthsession --policy-session -S session.dat
tpm2_policypcr -S session.dat -l "sha256:23"  -L policy.dat
tpm2_encryptdecrypt -Q --iv iv.bin  -c aes.ctx -d -o plain.out cipher.out  -p"session:session.dat"
tpm2_flushcontext -t &&  tpm2_flushcontext -s  &&  tpm2_flushcontext -l


tpm2_encodeobject -C primary.ctx -u key.pub -r key.priv -o private.pem

openssl asn1parse -inform PEM -in private.pem
*/

const (
	pcr = 23
)

const ()

var (
	tpmPath = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	in      = flag.String("in", "private.pem", "PEM file")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func OpenTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {

	flag.Parse()

	rwc, err := OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()

	rwr := transport.FromReadWriter(rwc)

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcr),
			},
		},
	}

	expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
	if err != nil {
		log.Printf("ERROR:  could not get PolicySession: %v", err)
		return
	}

	e, err := tpm2.CPBytes(tpm2.PolicyPCR{
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	})
	if err != nil {
		log.Fatalf("error executing CPBytes: %v", err)
	}

	// the cpbytes should be the same commandParameter as above
	log.Printf("PolicyPCR CPBytes %s\n", hex.EncodeToString(e))

	// now marshal each part and then concat them; thats the actual raw command thats run

	// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	pcrSelectionSegment := tpm2.Marshal(sel)
	pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: expectedDigest,
	})

	commandParameter := append(pcrDigestSegment, pcrSelectionSegment...)
	// 0020e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000001000b03000080
	log.Printf("pcrSelectionSegment %s", hex.EncodeToString(pcrSelectionSegment))
	log.Printf("pcrDigestSegment %s", hex.EncodeToString(pcrDigestSegment))

	log.Printf("commandParameter %s", hex.EncodeToString(commandParameter))

	////
	// start a session

	c, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: key.Parent,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary %q: %v", *tpmPath, err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	aesKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   tpm2.TPM2BName(primaryKey.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)

	if err != nil {
		log.Fatalf("can't load  hmacKey : %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: aesKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	//  now create a policy session and inject the parameters

	sess2, cleanup2, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(nil))}...)
	if err != nil {
		log.Fatalf("setting up policy session: %v", err)
	}
	defer cleanup2()

	tp2 := &tpm2.PolicyPCR{
		PolicySession: sess2.Handle(),
	}

	err = tpm2.ReqParameters(commandParameter, tp2)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	_, err = tp2.Execute(rwr)
	if err != nil {
		log.Fatalf("error generating requestParameters: %v", err)
	}

	data := []byte("foooo")

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		log.Fatalf("can't read rsa details %q: %v", *tpmPath, err)
	}

	keyAuth := tpm2.AuthHandle{
		Handle: aesKey.ObjectHandle,
		Name:   aesKey.Name,
		Auth:   sess2,
	}
	encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, false)

	if err != nil {
		log.Fatalf("EncryptSymmetric failed: %s", err)
	}
	log.Printf("IV: %s", hex.EncodeToString(iv))
	log.Printf("Encrypted %s", hex.EncodeToString(encrypted))

}

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    tpm2.TPMAlgCFB,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}
