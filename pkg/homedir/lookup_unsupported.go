// +build !darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd,!solaris

package homedir

import "io"

func GetPasswdPath() (string, error) {
	return "", ErrUnsupported
}

func GetPasswd() (io.ReadCloser, error) {
	return nil, ErrUnsupported
}

func GetGroupPath() (string, error) {
	return "", ErrUnsupported
}

func GetGroup() (io.ReadCloser, error) {
	return nil, ErrUnsupported
}
