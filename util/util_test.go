package util

import (
	"bytes"
	"testing"
	"unsafe"
)

const offset = 3

var (
	byteArr = []byte{'a', 'b', 'c', 'd'}
	ptrArr  = []*int{&a, &b, &c, &d}
	a       = 1
	b       = 2
	c       = 3
	d       = 4
)

// Make sure the address behaves well under slicing
func TestPtrOffset(t *testing.T) {
	i1 := uintptr(Ptr(byteArr[offset:]))
	i2 := uintptr(Ptr(byteArr))

	if i1 != i2+offset {
		t.Errorf("pointers %v and %v do not have an offset of %v", i1, i2, offset)
	}
}

// Tests that the ByteSlice method essentially reverses the Ptr method
func TestByteSlice(t *testing.T) {
	ptr := Ptr(byteArr)
	generatedArr := ByteSlice(ptr)[:len(byteArr)]

	if !bytes.Equal(byteArr, generatedArr) {
		t.Errorf("generated array (%v) and original array (%v) do not agree",
			generatedArr, byteArr)
	}
}

// Tests that the PointerSlice method correctly handles Go Pointers
func TestPointerSlice(t *testing.T) {
	arrPtr := unsafe.Pointer(&ptrArr[0])

	// Convert an array of unsafe pointers to int pointers.
	for i, ptr := range PointerSlice(arrPtr)[:len(ptrArr)] {
		if ptrArr[i] != (*int)(ptr) {
			t.Errorf("generated array and original array disagree at %d", i)
		}
	}
}

// Make sure NeverError actually panics
func TestNeverErrorPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NeverError did not panic")
		}
	}()

	err := SystemError("Hello")
	NeverError(err)
}

// Make sure NeverError doesn't panic on nil
func TestNeverErrorNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NeverError panicked")
		}
	}()

	NeverError(nil)
}

func TestIsKernelVersionAtLeast(t *testing.T) {
	// Even just running Go requires at least v2.6.23, so...
	if !IsKernelVersionAtLeast(2, 6) {
		t.Error("IsKernelVersionAtLeast() is broken")
	}
}
