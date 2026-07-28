//go:build !linux && !darwin

package linespeed

import "os"

func ownedByEffectiveUser(os.FileInfo) bool { return false }

func trustedManagedDirectory(string) bool { return false }
