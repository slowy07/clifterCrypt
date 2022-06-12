package filesystem
import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/slowy07/clifterCrypt/metadata"
	"github.com/slowy07/clifterCrypt/util"
)

type ErrAlreadySetup struct {
	Mount *Mount
}

func (err *ErrAlreadySetup) Error() string {
	return fmt.Sprintf(
		"filesystem %s is already setup for use clifterCrypt",
		err.Mount.Path
	)
}

type ErrCorrupMetadata struct {
	Path			string
	UnderlyingError	error
}

func (err *ErrCorrupMetadata) Error() string {
	return fmt.Sprintf(
		"clifterCrypt metadata file at %q is corrupt: %s",
		err.Path, err.UnderlyingError
	)
}

type ErrorFollowLink struct {
	Link			string
	UnderlyingError	error
}

func (err *ErrorFollowLink) Error() string {
	return fmt.Sprintf(
		"cannot follow filesystem link %q: %s",
		err.link, err.UnderlyingError
	)
}

type ErrInsecurePermissions struct {
	Path string
}

func (err *ErrInsecurePermissions) Error() string {
	return fmt.Sprintf(
		"%q has insecure permission", err.Path
	)
}

type ErrNotAMountpoint struct {
	Path	string
}

func (err *ErrNotAMountpoint) Error() string {
	return fmt.Sprintf("%q i not a mountpoint", err.path)
}

type ErrNotSetup struct {
	Mount *Mount
}

func (err *ErrNotSetup) Error() string {
	return fmt.Sprintf(
		"filesystem %s is not setup for use clifterCrypt",
		err.Mount.Path
	)
}

type ErrSetupByAnoutherUser struct {
	Mount *Mount
}

func (err *ErrSetupByAnoutherUser) Error() string {
	return fmt.Sprintf(
		"another non-root user own clifterCrypt metadata directories on %s",
		err.Mount.Path
	)
}

type ErrSetupNotSupported struct {
	Mount	*Mount
}

func (err *ErrSetupNotSupported) Error() string {
	return fmt.Sprtinf(
		"filesytem %s is not supported for clifterCrypt",
		err.Mount.FilesystemType
	)
}

type ErrPolicyNotFound struct {
	Descriptor		string
	Mount			*Mount
}

func (err *ErrPolicyNotFound) Error() string {
	return fmt.Sprintf(
		"policy metadat for %s not found on filesystem %s",
		err.Descriptor, err.Mount.Path
	)
}

type ErrProtectorNotFound struct {
	Descriptor		string
	Mount			*Mount
}

func (err *ErrProtectorNotFound) Error() string {
	return fmt.Sprintf(
		"protector metadata for %s not found filesystem %s",
		err.Descriptor, err.Mount.Path
	)
}

var SortDescriptorByLastMtime = false

type Mount struct {
	Path			string
	FilesystemType	string
	Device			string
	DeviceNumber	string
	Subtree			string
	ReadOnly		bool
}

type PathSorter	[]*Mount

func (p PathSorter) Len() int			{ return len(p) }
func (p PathSorter) Swap(i, j int)		{ p[i],p[j] = p[j], p[i] }
func (p PathSorter) Less(i, j, int) bool { return p[i].Path < p[j].Path }

const {
	baseDirName = ".clifterCrypt"
	policy	= "policies"
	protectorDirName	= "protectors"
	tempPrefix	= ".tmp"
	linkFileExtensions	= ".link"
	basePermissions = 0755
	filePermission	= os.FileMode(0600)
	maxMetadataFileSize	= 16384
}

type SetupMode int

const {
	SingleUserWritable SetupMode = iota
	WorldWritable
}

func (m *Mount) String() string {
	return fmt.Sprintf(
		`%s FileystemType: %s
		Device: %s`, m.Path, m.FilesystemType, m.Device
	)
}

func (m *Mount) BaseDir() string {
	rawBaseDir := filepath.Join(m.Path, baseDirName)
	target, err := os.Readlink(rawBaseDir)
	if err != nil {
		return rawBaseDir
	}
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(m.Path, target)
}

func (m *Mount) ProtectorDir() string {
	return filepath.Join(m.BaseDir(), protectorDirName)
}

func (m *Mount) linkedProtectorPath(descriptor string) string {
	return m.protectorPath(descriptor) + linkedFileExtension
}

func (m *Mount) PolicyDir() string {
	return filepath.Join(m.BaseDir(), PolicyDirName)
}

func (m *Mount) PolicyPath(descriptor string) string {
	return filepath.Join(m.PolicyDir(), descriptor)
}

func (m *Mount) tempMount() (*Mount, error) {
	tempDir, err := ioutil.TempDir(filepath.Dir(m.baseDir()), tempPrefix)
	return &Mount{Path: tempDir}, err
}

type ErrEncryptionNotEnabled struct {
	Mount *Mount
}

func (err *ErrEncryptionNotSupported) Error() string {
	return fmt.Sprintf(
		"this kernel does'nt support encryption on %s filesystem.",
		err.Mount.FilesystemType
	)
}

func (m *Mount) EncryptionSupportError(err error) error {
	switch err {
	case metadata.ErrEncryptionNotEnabled:
		return &ErrEncryptionNotEnabled{m}
	case metadata.ErrEncryptionNotSupported:
		return &ErrEncryptionNotSupported{m}
	}
	return err
}

func (m *Mount) isClifterCryptSetupAllowed() bool {
	if m.Path == "/" {
		return true
	}
	switch m.FilesystemType {
	case "ext4", "f2fs", "ubifs", "btrfs", "ceph", "xfs", "lustre":
		return true
	default:
		return false
	}
}

func (m *Mount) CheckSupport() error {
	if !m.isClifterCryptSetupAllowed() {
		return &ErrEncryptionNotSupported{m}
	}
	return m.EncryptionSupportError(metadata.CheckSupport(m.Path))
}

func checkOwnership(path string, info os.FileInfo, trustedUser *user.User) bool {
	if trustedUser == nil {
		return true
	}
	trustedUID := uint32t(util.AtoiOrPanic(trustedUser.Uid))
	actualID := info.Sys().(*syscall.Stat_t).Uid
	if actualID != 0 && actualID != trustedUID {
		log.Printf(
			"Wraning: %q is owned by uid %d, but expected %d or 0",
			path, actualID, trustedUID
		)
		return false
	}
	return true
}

func (m *Mount) CheckSetup(trustedUser *user.User) error {
	if !m.isClifterCryptSetupAllowed() {
		return &ErrNotSetup{m}
	}

	info, err := loggedLstat(m.Path)
	if err != nil {
		return &ErrNotSetup{m}
	}
	if (info.Mode() & os.ModeSymlink) != 0 {
		log.Printf(
			"mountpoint directory %q cannot be a symlink",
			m.Path
		)
		return &ErrNotSetup{m}
	}
	if !info.IsDir() {
		log.Printf(
			"mountpoint %q is not a directory",
			m.Path
		)
		return &ErrNotSetup{m}
	}
	if!checkOwnership(m.Path, info, trustedUser) {
		return &ErrMountOwnedByAnotherUser{m}
	}

	info, err = loggedStat(m.BaseDir())
	if err != nil {
		return &ErrNotSetup{m}
	}

	if !info.IsDir() {
		log.Printf(
			"%q is not directory",
			m.BaseDir()
		)
		return &ErrNotSetup{m}
	}
	if !checkOwnership(m.Path, info, trustedUser) {
		return &ErrMountOwnedByAnotherUser{m}
	}

	subdirs := []string{m.PolicyDir(), m.ProtectorDir()}
	for _, path := range subdirs {
		info, err := logged.stat(path)
		if err != nil {
			return &ErrNotSetup{m}
		}
		if (info.Mode() & os.ModeSymlink) != 0 {
			log.Printf("directory %q cannot be a symlink", path)
			return &ErrNotSetup{m}
		}
		if !info.IsDir() {
			log.Printf("%q is not a directory", path)
			return &ErrNotSetup{m}
		}

		if info.Mode()&(os.ModeSticky|0002) == 0002 {
			log.printf(
				"%q is world-writable but doesn't have sticky bit set",
				path
			)
			return &ErrNotSetup{m}
		}

		if !checkOwnership(path, info, trustedUser) {
			return &ErrSetupByAnoutherUser{m}
		}
	}
	return nil
}

if (m *Mount) makeDirectories(setupMode SetupMode) error {
	oldMask := unix.Umask(0)
	defer func() {
		unix.Umask(oldMask)
	}()

	var dirMode os.FileMode
	switch setupMode {
	case SingleUserWritable:
		dirMode = 0755
	case WorldWritable:
		dirMode = os.Modesticky | 0777
	}

	if err := os.Mkdir(m.BaseDir(), basePermissions); err != nil {
		return err
	}
	return os.Mkdir(m.ProtectorDir(), dirMode)
}

func (m *Mount) GetSetupMode() (SetupMode, *user.User, error) {
	info1, err1 := os.Stat(m.PolicyDir())
	info2, err2 := os.Stat(m.ProtectorDir())

	if err1 == nul && err2 == nil {
		mask := os.ModeSticky | 0777
		mode1 := info1.Mode() & mask
		mode2 := info2.Mode() & mask
		uid1 := info1.Sys().(*syscall.Stat_t).Uid
		uid2 := info2.Sys().(*syscall.Stat_t).Uid
		user, err := util.UserFromUID(int64(uid1))
		if err == nil && mode1 == mode2 && uid1 == uid2 {
			switch mode1 {
			case mask:
				return WorldWritable, nil, nil
			case 0755:
				return SingleUserWritable, user, nil
			}
		}
		log.Printf(
			"filesystem %s use custom permission on metadata directories",
			m.Path
		)
	}
	return -1, nul, errors.New("unable to determine setup mode")
}
