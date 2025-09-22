package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var seed string
var seedF string

var encode bool
var std bool
var decode bool

var rootCmd = &cobra.Command{Use: "goed", Short: "Use it to generate, sign and check ed25519 gpg keys"}
var generateCmd = &cobra.Command{
	Use:   "generate [private key output] [public key output]",
	Short: "Generate 2 keys files",
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		outpriv := "ed25519key.pem"
		outpub := "ed25519public_key.pem"
		if len(args) > 0 {
			outpriv = args[0]
			if len(args) > 1 {
				outpub = args[1]
			}
		}

		var priv ed25519.PrivateKey
		var pub ed25519.PublicKey
		var err error

		if len(seed) > 0 {
			priv = ed25519.NewKeyFromSeed([]byte(seed))
			pub = priv.Public().(ed25519.PublicKey)
			goto jump
		} else if len(seedF) > 0 {
			seed, err := os.ReadFile(seedF)
			if err != nil {
				fmt.Printf("error reading seed file (%s)\n%s\n", seedF, err.Error())
				os.Exit(1)
			}
			priv = ed25519.NewKeyFromSeed([]byte(seed))
			pub = priv.Public().(ed25519.PublicKey)
			goto jump
		}

		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Println("error generating pairs of random keys\n", err)
			os.Exit(1)
		}

	jump:

		var encodedpriv string
		var encodedpub string
		if encode {
			encodedpriv = base64.StdEncoding.EncodeToString(priv)
			encodedpub = base64.StdEncoding.EncodeToString(pub)
			if std {
				goto printbase64
			}
			priv = []byte(encodedpriv)
			pub = []byte(encodedpub)

		}

		if std {
			goto printresult
		}

		if err := os.MkdirAll(filepath.Dir(outpriv), 0774); err != nil {
			fmt.Printf("error writting private key in the file (%s)\n%s\n", outpriv, err.Error())
			os.Exit(1)
		}

		if err := os.MkdirAll(filepath.Dir(outpub), 0774); err != nil {
			fmt.Printf("error writting public key in the file (%s)\n%s\n", outpub, err.Error())
			os.Exit(1)
		}

		if err := os.WriteFile(outpriv, priv, 0440); err != nil {
			fmt.Printf("error writting private key in the file (%s)\n%s\n", outpriv, err.Error())
			os.Exit(1)
		}
		if err := os.WriteFile(outpub, pub, 0444); err != nil {
			fmt.Printf("error writting public key in the file (%s)\n%s\n", outpub, err.Error())
			os.Exit(1)
		}

		os.Exit(0)

	printresult:

		fmt.Printf("-- PRIVATE KEY --\n%b", priv)
		fmt.Printf("-- PUBLIC KEY --\n%b", pub)
		os.Exit(0)

	printbase64:
		fmt.Println("-- PRIVATE KEY --\n", encodedpriv)
		fmt.Println("-- PUBLIC KEY --\n", encodedpub)
	},
}

var signCmd = &cobra.Command{
	Use:   "sign {private key file} {target file} [output file]",
	Short: "Sign a file generating a signature file",
	Args:  cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		priv := args[0]
		target := args[1]
		sigoutput := fmt.Sprintf("%s.sig", target)

		if len(args) > 2 {
			sigoutput = args[2]
		}

		private, err := os.ReadFile(priv)
		if err != nil {
			fmt.Printf("error reading private key (%s)\n%s\n", priv, err.Error())
			os.Exit(1)
		}
		if decode {

			private, err = base64.StdEncoding.DecodeString(string(private))
			if err != nil {
				fmt.Println("error decoding base64 string\n", err)
			}
		}

		targetFile, err := os.ReadFile(target)
		if err != nil {
			fmt.Printf("error reading private key (%s)\n%s\n", priv, err.Error())
			os.Exit(1)
		}

		var encodedsig string
		sig := ed25519.Sign(ed25519.PrivateKey(private), targetFile)
		if encode {

			encodedsig = base64.StdEncoding.EncodeToString(sig)
			sig = []byte(encodedsig)
		}

		if std {
			if encode {
				goto sigbase64
			}
			goto sigprint
		}

		if err := os.MkdirAll(filepath.Dir(sigoutput), 0774); err != nil {
			fmt.Printf("error writting signature in the file (%s)\n%s\n", sigoutput, err.Error())
			os.Exit(1)
		}

		if err := os.WriteFile(sigoutput, sig, 0444); err != nil {
			fmt.Printf("error writting signature in the file (%s)\n%s\n", sigoutput, err.Error())
			os.Exit(1)
		}

		os.Exit(0)

	sigprint:
		fmt.Printf("%b", sig)
		os.Exit(0)

	sigbase64:
		fmt.Printf("%s", encodedsig)
		os.Exit(0)
	},
}

var randomSeedCmd = &cobra.Command{
	Use:   "seed",
	Short: "Generate a random seed, retuns it encoded on base64",
	Run: func(cmd *cobra.Command, args []string) {
		seed := make([]byte, 32)
		rand.Read(seed)
		fmt.Println(base64.StdEncoding.EncodeToString(seed))
	},
}

var checkCmd = &cobra.Command{
	Use:   "check {public key} {file} {signature}",
	Short: "Check the file with the file signature and public key",
	Args:  cobra.RangeArgs(3, 3),
	Run: func(cmd *cobra.Command, args []string) {
		pub := args[0]
		target := args[1]
		sigtarget := args[2]

		sigF, err := os.ReadFile(sigtarget)
		if err != nil {
			fmt.Printf("error reading signature (%s)\n%s\n", sigtarget, err.Error())
			os.Exit(1)
		}

		public, err := os.ReadFile(pub)
		if err != nil {
			fmt.Printf("error reading private key (%s)\n%s\n", pub, err.Error())
			os.Exit(1)
		}
		if decode {

			public, err = base64.StdEncoding.DecodeString(string(public))
			if err != nil {
				fmt.Println("error decoding base64 string\n", err)
			}
			sigF, err = base64.StdEncoding.DecodeString(string(sigF))
			if err != nil {
				fmt.Println("error decoding base64 string\n", err)
			}
		}

		f, err := os.ReadFile(target)
		if err != nil {
			fmt.Printf("error reading file (%s)\n%s\n", target, err.Error())
			os.Exit(1)
		}

		if ed25519.Verify(ed25519.PublicKey(public), f, sigF) {
			fmt.Println("true")
		} else {
			fmt.Println("false")
		}

		os.Exit(0)

	},
}

func main() {

	generateCmd.Flags().StringVarP(&seed, "seed", "s", "", "seed to generate the pair of keys")
	generateCmd.Flags().StringVarP(&seedF, "seedfile", "f", "", "reads the seed from a file to generate the pair of keys")
	generateCmd.Flags().BoolVarP(&encode, "base64", "b", false, "encode the result into base64")
	generateCmd.Flags().BoolVarP(&std, "stdout", "o", false, "throws the output in stdout")
	rootCmd.AddCommand(generateCmd)

	signCmd.Flags().BoolVarP(&std, "stdout", "o", false, "throws the output in stdout")
	signCmd.Flags().BoolVarP(&encode, "base64", "b", false, "encode the result into base64")
	signCmd.Flags().BoolVarP(&decode, "decode", "d", false, "decode the private key with base64")
	rootCmd.AddCommand(signCmd)

	rootCmd.AddCommand(randomSeedCmd)

	checkCmd.Flags().BoolVarP(&decode, "decode", "d", false, "decode the private key and signature with base64")

	rootCmd.AddCommand(checkCmd)
	rootCmd.Execute()
}
