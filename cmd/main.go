package main

import (
	"encoding/base64"
	"fmt"

	base58 "github.com/mr-tron/base58/base58"
	"github.com/yottachain/YTCrypto"
)

func main() {
	bytes, err := base64.StdEncoding.DecodeString("CAASqQkwggSlAgEAAoIBAQCrVnUersoiK+4J/GW68wNa8nw/iSa2vq47SqjINX4Q2gPBDgZ3g1uNjnyniPaWH79HLkpjN3OcqyUPK6ZzX/jFMqBbZqHCO483ird9mPrCmzFZMnJyQPXMqLv0v8uFwrQGDD8HBE31weQvoPagaTdS44fFVpTr4uF6OhTZCLaDOEuIBWmLxe0Vag18ur6rym5Wb5ipi6TKjGHprjnpBXWWa+L3Lz7ia+ID17XRzm9j7l/dVRERDJJu397B5ykU46BhreS0Qa7hITtiKdpqbz726DD3tU2WnD3w+egT+qevuhxufW0369DsUz60gsI0B6j/6mBC7CFTcDH91U2QO22pAgMBAAECggEBAIzqvcbvgSXbtZqW8OBycCcD2nazCZkxeMEhJXIMtNONS5sjOuResBTbxOBRwGU2VS5o/xtdBwQqqn8wqmSn4UXm3oZuAcprC95lg4aUJGGcHFk9KW2YydB6UqP4fp5TxZZXyhquSqQ+xLr7ivvhrXPJ2OfPzwm2/zV0waLDDMEcWbjCJwQAFIFBYzs6jBI/VEf3VLXx5PjYmbC1PSahvEvUJLQ22iVm9zcHWrxIXp/HxjSle8SREUxWVPvKu7u13wUPjxnpQ7o19uca1+qfIJPds658v+biUOKLOY5PLug3gnDT8rf/nptzgfp9y++igO7IIGL5R+HPag6rl1YSi1ECgYEA3nx8yyljCYU30SI/pg6FMQDhokhbgba8I8grWeXo2PuUrAK3MZW/m3X7QM/jf82p61zdasNs45Fyj0Aynn8zlX83QNuUOudFctxka/TMFGCVdgSNlia8Taw4/Pn3BF4Yw4u2NFZI/PGB79pbEsp7T/KrgkxgxZjmlgNymCBptw0CgYEAxSWUinbjonJdjtMeLTCexNgTcns9miNGYfbKT+odr3n6J2E7wYj8VFFtLbmJHxcakdxk+QsJi03M+iiS3YIKhBroasKzOuZOd7l/qEDbRn/u1SC9AQzqCq5QdeDBkAeKqSUqBbmv1EOu31qoO1MBWQp3hIVfEM5Bfopj+NjpKg0CgYEAmtdS1uYP6jFP/nnyiDR01/0AC7yGCwnNeK24FhHfcxvshaZCLv1EZALBgYLtlyXgi1CPPN2Tq/GvJCmO0SZAFVx7bOUlDbWlbOIb9dJiMhBiFMfobka5KOmio9Wn599BJt7WSSiAFaJTR0XVuoc3ORXv7XgQpZTbbi4qE9wDFwUCgYBxXPO2TzkEL0k3GJTwnVWekTVVjiJVINWW/WdGXrQlNDmxLUtENXYLMitasKZ1lz5zA02Ym00oqlskufIBp4ZOgn6E7WJMiyQx2hva7zhnqKb4LPQhx4BJFgU0U0JahMuqCbHJSwYdQ7IpwyKbwlYzEj65mEubCU9F6WQlMu2YfQKBgQCTcRD7UfMI1T2JcCyQvSrQdDp2nDLFKaYQWI//zXMdmejTmM15olePJn3tBVV92zQHX3n4AER0T83Q+PcMSuCWFmUa4fN9xDVrGETjliP7+PhoD4r2jAPu9WdDPKxHIou0XJZnSCihJ4mYoesmMXxr/KljBx0kwQK12JR4AmEKxA==")
	if err != nil {
		panic(err.Error())
	}
	sk := base58.Encode(bytes[2:1194])
	skk, err := YTCrypto.ConvertStringToKey(sk, YTCrypto.RSAPRIV)
	if err != nil {
		panic(err.Error())
	}
	fmt.Println(skk.Raw())
	pk, err := YTCrypto.GetRsaPublicKeyByPrivateKey(sk)
	if err != nil {
		panic(err.Error())
	}
	pkk, err := YTCrypto.ConvertStringToKey(pk, YTCrypto.RSAPUB)
	fmt.Println(pkk.Raw())

}
