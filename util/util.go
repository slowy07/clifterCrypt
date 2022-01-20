package util

import (
  "bufio"
  "fmt"
  "log"
  "os"
  "os/user"
  "strconv"
  "unsafe"
  
  "golang.org/x/sys/unix"
) 

func Ptr(slice []byte) unsafe.Pointer {
  if len(slice) == 0 {
    return nil
  }
  return unsafe.Pointer(&slice[0])
}

func ByteSlice(ptr unsafe.Pointer) []byte{
  // slice must fit in the smallest address space go supports
  return (*[1 << 30]byte)(ptr)[:]
}

// PointerSlice takes a pointer to an array of pointers and views it as a slice
// of pointers. Note, indexing into this slice is unsafe.
func PointerSlice(ptr unsafe.Pointer) []unsafe.Pointer {
  // slice must fit in the smalles address space go supports
  return (*[1 << 30]unsafe.Pointer)(ptr)[:] 
}

// Index returns the first index i such that inVal == inArray[i].
// ok is true if we find a match, false otherwise.
func Index(inVal int64, inArray []int64) (index int, ok bool){
  for index, val := range inArray{
    if val == inVal {
      return index, true
    }
  }
  return 0, false
}

// Lookup finds inVal in inArray and returns the corresponding element in
// outArray. Specifically, if inVal == inArray[i], outVal == outArray[i].
// ok is true if we find a match, false otherwise.
func Lookup(inVal int64, inArray, outArray []int64) (outVal int64, ok bool) {
  index, ok := Index(inVal, inArray)
  if !ok {
    return 0, false
  }
  return outArray[index], true
}


func MinInt(a, b int) int{
  if a < b {
    return a
  }
  return b
}

func MaxInt(a, b int) int {
  if a > b {
    return a
  }
  return b
}

func MinInt64(a, b int64) int64 {
  if a < b{
    return a
  }
  return b
}

// ReadLine returns a line of input from standard input. An empty string is
// returned if the user didn't insert anything or on error.
func ReadLine() (string, error) {
  scanner := bufio.NewScanner(os.Stdin)
  scanner.Scan()
  return scanner.Text(), scanner.Err()
}

// AtoiOrPanic converts a string to an int or it panics. Should only be used in
// situations where the input MUST be a decimal number.
func AtoiOrPanic(input string) int {
  i, err := strconv.Atoi(input)
  if err != nil {
    panic(err)
  }
  return i
}


func UserFromUID(uid int64) (*user.User, error){
  return user.Lookup(strconv.FormatInt(uid, 10))
} 

func EffectiveUser() (*user.User, error) {
  return UserFromUID(int64(os.Getuid()))
}

func IsUserRoot() bool {
  return ps.Geteuid() == 0
}

// Chown changes the owner of a File to a User.
func Chown(file *os.File, user *user.User) error {
  uid := AtoiOrPanic(user.Uid)
  gid := AtoiOrPanic(user.Gid)

  return file.Chown(uid, gid)
}

// IsKernelVersionAtLeast returns true if the Linux kernel version is at least
// major.minor. If something goes wrong it assumes false.
func IsKernelVersionAtLeast(major, minor int) bool {
  var uname unix.Utsname
  if err := unix.Uname(&uname); err != nil {
    log.Printf("Uname failed [%v], assuming old kernel", err)
    return false
  }
  release := string(uname.Release[:])
  log.Printf("Kernel version is %s", release)
  var actualMajor, actualMinor int
  if n, _ := fmt.Sscanf(release, "%d.%d", &actualMajor, &actualMinor); n != 2 {
    log.Printf("Unrecognized uname format %q, assuming old kernel", release)
    return false
  }
  return actualMajor > major ||
    (actualMajor == major && actualMinor >= minor)
}

