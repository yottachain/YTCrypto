package YTCrypto

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

var (
	privKey string
	pubKey  string
)

func TestMain(m *testing.M) {
	privKey, pubKey = CreateKey()
	if privKey == "" || pubKey == "" {
		panic("Create key pair failed")
	}
	fmt.Printf("Createkey pair success,private key is %s and public key is %s\n", privKey, pubKey)
	os.Exit(m.Run())
}

func TestGetPublicKeyByPrivateKey(t *testing.T) {
	pubKey2, err := GetPublicKeyByPrivateKey(privKey)
	if err != nil {
		t.Error(err.Error())
	}
	if pubKey != pubKey2 {
		t.Error("Generate public key by private key failed.")
	}
}

func TestEcrecover(t *testing.T) {
	sig, err := Sign(privKey, []byte("123456"))
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("generate signature for string '%s', signature is %s\n", "123456", sig)
	pk, err := Ecrecover([]byte("123456"), sig)
	if err != nil {
		t.Error(err.Error())
	}
	if pk != pubKey {
		t.Error("verify signature failed")
	}
}

func TestSignAndVerify(t *testing.T) {
	sig, err := Sign(privKey, []byte("123456"))
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("generate signature for string '%s', signature is %s\n", "123456", sig)
	ret := Verify(pubKey, []byte("123456"), sig)
	if !ret {
		t.Error("verify signature failed")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	ecData, err := ECCEncrypt([]byte("123456"), pubKey)
	if err != nil {
		t.Error(err.Error())
	}
	data, err := ECCDecrypt(ecData, privKey)
	if err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(data, []byte("123456")) {
		t.Errorf("decrypted data is not equal to original data: %s and %s\n", string(data), "123456")
	}
}

func BenchmarkCreateKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = CreateKey()
	}
}

func BenchmarkCreateKeyParallel(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = CreateKey()
		}
	})
}

func BenchmarkSignAndVerify(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		testData := []byte(fmt.Sprintf("test%d", i))
		sig, err := Sign(privKey, testData)
		if err != nil {
			b.Error(err.Error())
		}
		if !Verify(pubKey, testData, sig) {
			b.Error("verify failed")
		}
	}
}

func BenchmarkSignAndVerifyParallel(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			testData := []byte(fmt.Sprintf("test%d", i))
			sig, err := Sign(privKey, testData)
			if err != nil {
				b.Error(err.Error())
			}
			if !Verify(pubKey, testData, sig) {
				b.Error("verify failed")
			}
			i += 1
		}
	})
}

func BenchmarkEncryptAndDecrypt(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		testData := []byte(fmt.Sprintf("test%d", i))
		ecData, err := ECCEncrypt(testData, pubKey)
		if err != nil {
			b.Error(err.Error())
		}
		data, err := ECCDecrypt(ecData, privKey)
		if err != nil {
			b.Error(err.Error())
		}
		if !bytes.Equal(testData, data) {
			b.Errorf("encrypt/decrypt failed")
		}
	}
}

func BenchmarkEncryptAndDecryptParallel(b *testing.B) {
	b.StopTimer()
	b.StartTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			testData := []byte(fmt.Sprintf("test%d", i))
			ecData, err := ECCEncrypt(testData, pubKey)
			if err != nil {
				b.Error(err.Error())
			}
			data, err := ECCDecrypt(ecData, privKey)
			if err != nil {
				b.Error(err.Error())
			}
			if !bytes.Equal(testData, data) {
				b.Errorf("encrypt/decrypt failed")
			}
			i += 1
		}
	})
}
