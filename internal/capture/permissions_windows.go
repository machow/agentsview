//go:build windows

package capture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func createSecureCaptureDirectory(path string) error {
	allowed, err := captureDirectorySIDs()
	if err != nil {
		return err
	}
	descriptor, err := captureDirectorySecurityDescriptor(allowed)
	if err != nil {
		return err
	}
	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pathUTF16, &attributes); err != nil {
		return err
	}
	runtime.KeepAlive(descriptor)
	return verifyCaptureDirectoryDACL(path, allowed)
}

func captureDirectorySecurityDescriptor(
	allowed []*windows.SID,
) (*windows.SECURITY_DESCRIPTOR, error) {
	if len(allowed) == 0 {
		return nil, errors.New("capture directory has no trusted principals")
	}
	var sddl strings.Builder
	sddl.WriteString("O:")
	sddl.WriteString(allowed[0].String())
	sddl.WriteString("D:P")
	for _, sid := range allowed {
		sddl.WriteString("(A;OICI;GA;;;")
		sddl.WriteString(sid.String())
		sddl.WriteByte(')')
	}
	return windows.SecurityDescriptorFromString(sddl.String())
}

func verifyCaptureParentSafety(path string) error {
	allowed, err := captureDirectorySIDs()
	if err != nil {
		return err
	}
	for parent := filepath.Dir(filepath.Clean(path)); ; parent = filepath.Dir(parent) {
		if err := verifyWindowsParentDACL(parent, allowed); err != nil {
			return fmt.Errorf("unsafe capture parent %q: %w", parent, err)
		}
		if parent == filepath.Dir(parent) {
			return nil
		}
	}
}

func verifyWindowsParentDACL(path string, allowed []*windows.SID) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	return verifyWindowsParentSecurity(descriptor, allowed)
}

func verifyWindowsParentSecurity(
	descriptor *windows.SECURITY_DESCRIPTOR,
	allowed []*windows.SID,
) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !captureSIDAllowed(owner, allowed) {
		return errors.New("parent directory has an untrusted owner")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("parent directory has an unrestricted DACL")
	}
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		directReplacement := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 &&
			ace.Mask&captureParentReplacementRights() != 0
		inheritedWrite := ace.Header.AceFlags&windows.CONTAINER_INHERIT_ACE != 0 &&
			ace.Mask&captureInheritedWriteRights() != 0
		if (!directReplacement && !inheritedWrite) ||
			ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("parent DACL has an unsupported replacement-capable ACE")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !captureSIDAllowed(sid, allowed) {
			return errors.New("parent DACL permits replacement by another principal")
		}
	}
	return nil
}

func captureParentReplacementRights() windows.ACCESS_MASK {
	const fileDeleteChild windows.ACCESS_MASK = 0x40
	return windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_ALL | fileDeleteChild
}

func captureInheritedWriteRights() windows.ACCESS_MASK {
	const (
		fileAddFile         windows.ACCESS_MASK = 0x2
		fileAddSubdirectory windows.ACCESS_MASK = 0x4
		fileDeleteChild     windows.ACCESS_MASK = 0x40
	)
	return windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.GENERIC_WRITE | windows.GENERIC_ALL | fileAddFile |
		fileAddSubdirectory | fileDeleteChild
}

func captureSIDAllowed(sid *windows.SID, allowed []*windows.SID) bool {
	for _, candidate := range allowed {
		if windows.EqualSid(sid, candidate) {
			return true
		}
	}
	return false
}

func secureCaptureDirectory(path string) error {
	if err := verifyCaptureDirectoryOwner(path); err != nil {
		return err
	}
	allowed, err := captureDirectorySIDs()
	if err != nil {
		return err
	}
	return applyCaptureDirectoryDACL(path, allowed)
}

func verifyCaptureDirectoryOwner(path string) error {
	if err := verifyCapturePathOwner(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("capture path is not a private directory")
	}
	return nil
}

func verifyCapturePathOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("capture state contains a symbolic link")
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	if owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return errors.New("capture state is not owned by the current user")
	}
	return nil
}

func applyCaptureDirectoryDACL(path string, allowed []*windows.SID) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(allowed))
	for _, sid := range allowed {
		pinner.Pin(sid)
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return err
	}
	return verifyCaptureDirectoryDACL(path, allowed)
}

func captureDirectorySIDs() ([]*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	var unique []*windows.SID
	for _, sid := range []*windows.SID{user.User.Sid, system, administrators} {
		duplicate := false
		for _, existing := range unique {
			if windows.EqualSid(existing, sid) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			unique = append(unique, sid)
		}
	}
	return unique, nil
}

func verifyCaptureDirectoryDACL(path string, allowed []*windows.SID) error {
	descriptor, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("capture directory DACL is not protected")
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if dacl == nil || defaulted || int(dacl.AceCount) != len(allowed) {
		return errors.New("capture directory DACL has unexpected entries")
	}
	seen := make([]bool, len(allowed))
	for index := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return errors.New("capture directory DACL has an unsafe entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for allowedIndex, candidate := range allowed {
			if windows.EqualSid(sid, candidate) {
				if seen[allowedIndex] {
					return errors.New("capture directory DACL repeats a principal")
				}
				seen[allowedIndex] = true
				matched = true
				break
			}
		}
		if !matched {
			return errors.New("capture directory DACL grants an unexpected principal")
		}
	}
	return nil
}
