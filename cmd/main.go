package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/mr-tron/base58"
	"github.com/yottachain/YTCrypto/crypto"
	"github.com/yottachain/YTCrypto/crypto/ecies"

	ytcrypto "github.com/yottachain/YTCrypto"
)

func ECCEncrypt(pt []byte, puk ecies.PublicKey) ([]byte, error) {
	ct, err := ecies.Encrypt(rand.Reader, &puk, pt, nil, nil)
	return ct, err
}

func ECCDecrypt(ct []byte, prk ecies.PrivateKey) ([]byte, error) {
	pt, err := prk.Decrypt(ct, nil, nil)
	return pt, err
}
func getKey() (*ecdsa.PrivateKey, error) {
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return prk, err
	}
	return prk, nil
}

func calculateHashcode(data string) string {
	nonce := 0
	var str string
	var check string
	pass := false
	var dif int = 4
	for nonce = 0; ; nonce++ {
		str = ""
		check = ""
		check = data + strconv.Itoa(nonce)
		h := sha256.New()
		h.Write([]byte(check))
		hashed := h.Sum(nil)
		str = hex.EncodeToString(hashed)
		for i := 0; i < dif; i++ {
			if str[i] != '0' {
				break
			}
			if i == dif-1 {
				pass = true
			}
		}
		if pass == true {
			return str
		}
	}
}

func main1() {
	var mt = "20181111"
	var pn = "18811881188"
	var ln = "001"
	var mn = "importantmeeting"
	var rn = "216"
	data := mt + pn + ln + mn + rn
	hdata := calculateHashcode(data)
	fmt.Println("信息串：", data)
	fmt.Println("sha256加密后：", hdata)
	bdata := []byte(hdata)
	prk, err := getKey()
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey
	endata, err := ECCEncrypt([]byte(bdata), puk2)
	if err != nil {
		panic(err)
	}
	fmt.Println("ecc公钥加密后：", hex.EncodeToString(endata))
	dedata, err := ECCDecrypt(endata, *prk2)
	if err != nil {
		panic(err)
	}
	fmt.Println("私钥解密：", string(dedata))
}

func main() {
	//_, err := ytcrypto.GetRawPrivateKey("5KHRhkG7X5tdd8inVjwL7GA6ez2SrXBrw9KLCJ4jW5Mygqf9LmG")

	pubkey, _ := base58.Decode("7Gt3ZySVmb7bDDXYW3jeaDJX85Q6N6ALCCwKNhCKYyK8ksBaus")
	fmt.Println("-------   " + hex.EncodeToString(pubkey))

	sig, err := ytcrypto.Sign("5J2XGbuK9L35VtxMKjEMWoCB3Aw7RdAVKuPizgqzwSgKLseXSYs", []byte("123456")) //只有R S，共64字节
	signature := strings.TrimPrefix(sig, "SIG_K1_")
	a, _ := base58.Decode(signature)
	fmt.Println(len(a))
	fmt.Println(ytcrypto.Verify("7Gt3ZySVmb7bDDXYW3jeaDJX85Q6N6ALCCwKNhCKYyK8ksBaus", []byte("123456"), sig))
	fmt.Println(sig)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(sig)
	}

	pubkey, _ = base58.Decode("8goL8rkhDAyLkVzwAhYUcHMNfHTAqFgJvw3W3LKu6ibXQ7pv2F")
	fmt.Println(hex.EncodeToString(pubkey))
	fmt.Println(len(pubkey))

	sig1, _ := base58.Decode("KUNpoQZM1zDkWi5g93u8S4cWjWfpfHmh3aC2iZHBFZWbeipRWRVVDvnevEoEBuGSLYExHdQHkP6MWr2dhQ8FThNjQEuEon") //EOS标准签名，69字节，
	fmt.Println(len(sig1))
	sig1[0] -= 31
	signx := append(sig1[1:65], sig1[0])
	pubkey, err = crypto.Ecrecover(sha256Sum([]byte("123456")), signx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(hex.EncodeToString(pubkey))

	rawsig := sig1[0:65]
	checksum := sig1[65:]
	a = sha256Sum(rawsig)
	b := sha256Sum(a)
	fmt.Println(hex.EncodeToString(b))
	fmt.Println(hex.EncodeToString(checksum))
	//fmt.Println(ytcrypto.Verify("EOS6EsCrE9rn4YrciB2MTifqmmLMYCU7GmEAfE1DS43oMFJ47UFq5", []byte("123456"), sig1[1:65]))
	// pk, _ := base58.Decode("5KHRhkG7X5tdd8inVjwL7GA6ez2SrXBrw9KLCJ4jW5Mygqf9LmG")
	// for _, b := range pk {
	// 	fmt.Printf("%x", b)
	// }
	// fmt.Println()
	// fmt.Println(len(pk))
	// crypto.ToECDSA(pk[1:40])

	sk, pk := ytcrypto.CreateKey()
	skb, _ := base58.Decode(sk)
	pkb, _ := base58.Decode(pk)
	fmt.Println(sk)
	fmt.Println(pk)
	fmt.Println(hex.EncodeToString(skb))
	fmt.Println(hex.EncodeToString(pkb))

	sign, _ := ytcrypto.Sign(sk, []byte("123456"))
	fmt.Println(sign)
	ok := ytcrypto.Verify(pk, []byte("1234567"), sign)
	fmt.Println(ok)

	ct, err := ytcrypto.ECCEncrypt([]byte("hahaha123"), pk)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(hex.EncodeToString(ct))
	pt, err := ytcrypto.ECCDecrypt(ct, sk)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(string(pt))
}

func sha256Sum(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}
