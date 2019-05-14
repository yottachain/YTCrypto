package main

/*
#cgo CFLAGS: -std=c99

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct keyret {
	char *privatekey;
	char *publickey;
} keyret;

typedef struct stringwitherror {
	char *str;
	char *error;
} stringwitherror;

typedef struct byteswitherror {
	char *data;
	long long size;
	char *error;
} byteswitherror;

*/
import "C"
import (
	"unsafe"

	ytcrypto "github.com/yottachain/YTCrypto"
)

//export CreateKey
func CreateKey() *C.keyret {
	privateKey, publicKey := ytcrypto.CreateKey()
	return createKeyret(privateKey, publicKey)
}

//export Sign
func Sign(privateKey *C.char, data *C.char, size C.longlong) *C.stringwitherror {
	dataSlice := (*[1 << 30]byte)(unsafe.Pointer(data))[:int64(size):int64(size)]
	signature, err := ytcrypto.Sign(C.GoString(privateKey), dataSlice)
	return createStringwitherror(signature, err)
}

//export Verify
func Verify(publicKey *C.char, data *C.char, size C.longlong, signature *C.char) C.int32_t {
	dataSlice := (*[1 << 30]byte)(unsafe.Pointer(data))[:int64(size):int64(size)]
	ret := ytcrypto.Verify(C.GoString(publicKey), dataSlice, C.GoString(signature))
	if ret {
		return 1
	} else {
		return 0
	}
}

//export ECCEncrypt
func ECCEncrypt(data *C.char, size C.longlong, publicKey *C.char) *C.byteswitherror {
	dataSlice := (*[1 << 30]byte)(unsafe.Pointer(data))[:int64(size):int64(size)]
	ecdata, err := ytcrypto.ECCEncrypt(dataSlice, C.GoString(publicKey))
	return createByteswitherror(C.CString(string(ecdata)), C.longlong(len(ecdata)), err)
}

//export ECCDecrypt
func ECCDecrypt(data *C.char, size C.longlong, privateKey *C.char) *C.byteswitherror {
	dataSlice := (*[1 << 30]byte)(unsafe.Pointer(data))[:int64(size):int64(size)]
	scdata, err := ytcrypto.ECCDecrypt(dataSlice, C.GoString(privateKey))
	return createByteswitherror(C.CString(string(scdata)), C.longlong(len(scdata)), err)
}

func createKeyret(privateKey string, publicKey string) *C.keyret {
	ptr := (*C.keyret)(C.malloc(C.size_t(unsafe.Sizeof(C.keyret{}))))
	C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.keyret{})))
	(*ptr).privatekey = C.CString(privateKey)
	(*ptr).publickey = C.CString(publicKey)
	return ptr
}

//export FreeKeyret
func FreeKeyret(ptr *C.keyret) {
	if ptr != nil {
		if (*ptr).privatekey != nil {
			C.free(unsafe.Pointer((*ptr).privatekey))
			(*ptr).privatekey = nil
		}
		if (*ptr).publickey != nil {
			C.free(unsafe.Pointer((*ptr).publickey))
			(*ptr).publickey = nil
		}
		C.free(unsafe.Pointer(ptr))
	}
}

func createStringwitherror(str string, err error) *C.stringwitherror {
	ptr := (*C.stringwitherror)(C.malloc(C.size_t(unsafe.Sizeof(C.stringwitherror{}))))
	C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.stringwitherror{})))
	if err != nil {
		(*ptr).error = C.CString(err.Error())
		return ptr
	}
	(*ptr).str = C.CString(str)
	return ptr
}

//export FreeStringwitherror
func FreeStringwitherror(ptr *C.stringwitherror) {
	if ptr != nil {
		if (*ptr).str != nil {
			C.free(unsafe.Pointer((*ptr).str))
			(*ptr).str = nil
		}
		if (*ptr).error != nil {
			C.free(unsafe.Pointer((*ptr).error))
			(*ptr).error = nil
		}
		C.free(unsafe.Pointer(ptr))
	}
}

func createByteswitherror(data *C.char, size C.longlong, err error) *C.byteswitherror {
	ptr := (*C.byteswitherror)(C.malloc(C.size_t(unsafe.Sizeof(C.byteswitherror{}))))
	C.memset(unsafe.Pointer(ptr), 0, C.size_t(unsafe.Sizeof(C.byteswitherror{})))
	if data != nil {
		(*ptr).data = data
		(*ptr).size = size
	}
	if err != nil {
		(*ptr).error = C.CString(err.Error())
	}
	return ptr
}

//export FreeByteswitherror
func FreeByteswitherror(ptr *C.byteswitherror) {
	if ptr != nil {
		if (*ptr).data != nil {
			C.free(unsafe.Pointer((*ptr).data))
			(*ptr).data = nil
		}
		if (*ptr).error != nil {
			C.free(unsafe.Pointer((*ptr).error))
			(*ptr).error = nil
		}
		C.free(unsafe.Pointer(ptr))
	}
}

func main() {

}
