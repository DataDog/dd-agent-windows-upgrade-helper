package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

//	"strconv"

type Handle uintptr

const GENERIC_READ uint32 = 0x80000000
const NO_ERROR syscall.Errno = 0
const ERROR_SERVICE_DOES_NOT_EXIST syscall.Errno = 1060

func isServiceInstalled() (installed bool, err error) {
	var hSCM uintptr
	var mod = syscall.NewLazyDLL("advapi32.dll")
	var openScManager = mod.NewProc("OpenSCManagerW")
	var openService = mod.NewProc("OpenServiceW")
	var closeServiceHandle = mod.NewProc("CloseServiceHandle")

	installed = false
	err = NO_ERROR
	hSCM, _, err = openScManager.Call(uintptr(0), uintptr(0), uintptr(GENERIC_READ))
	if hSCM == uintptr(0) {
		fmt.Printf("Failed to open SC Manager %s\n", err)
		return
	}
	hService, _, err := openService.Call(hSCM,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("DatadogAgent"))),
		uintptr(GENERIC_READ))
	if hService != uintptr(0) {
		installed = true
		closeServiceHandle.Call(hService)
		err = NO_ERROR
	} else {
		fmt.Printf("Failed to open Service %s\n", err)
	}

	if hSCM != uintptr(0) {
		closeServiceHandle.Call(uintptr(hSCM))
	}
	return
}

const ERROR_NO_MORE_DATA syscall.Errno = 259
const cchGUID int = 38

func findAndUninstallRelatedProducts(upgradeCode string, doUninstall bool) (bFound bool) {
	bFound = false
	var mod = syscall.NewLazyDLL("msi.dll")
	var MsiSetInternalUI = mod.NewProc("MsiSetInternalUI")
	var MsiEnumRelatedProducts = mod.NewProc("MsiEnumRelatedProductsW")
	var MsiConfigureProduct = mod.NewProc("MsiConfigureProductW")

	oldUiLevel, _, _ := MsiSetInternalUI.Call(uintptr(2), uintptr(0))
	buf := make([]uint16, cchGUID+1)
	var index uint32 = 0
	for retval := uintptr(NO_ERROR); retval == uintptr(NO_ERROR); {
		retval, _, _ = MsiEnumRelatedProducts.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(upgradeCode))),
			uintptr(0),
			uintptr(index),
			uintptr(unsafe.Pointer(&buf[0])))
		if retval == uintptr(NO_ERROR) {
			bFound = true
			if doUninstall {
				uninstret, _, _ := MsiConfigureProduct.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(0), uintptr(2))
				if uintptr(NO_ERROR) != uninstret {
					return false
				}
			}
		}
		index++
	}
	MsiSetInternalUI.Call(oldUiLevel, uintptr(0))
	return
}

//const oldUpgradeCode string = "{82210ed1-bbe4-4051-aa15-002ea31dde15}"

func mainfunc() int {
	// set up argument parsing
	var oldCode string
	var newCode string
	var checkOnly bool
	flag.StringVar(&oldCode, "oldcode", "", "Upgrade code of prior version")
	flag.StringVar(&newCode, "newcode", "", "Upgrade code of current version (does not uninstall)")
	flag.BoolVar(&checkOnly, "checkonly", false, "Don't trigger uninstall if found")
	flag.Parse()

	if oldCode == "" || newCode == "" {
		fmt.Printf("Missing Parameter")
		return -1
	}

	installed := findAndUninstallRelatedProducts(newCode, false)
	if installed {
		fmt.Printf("Found current product installed.")
		return 0
	}
	installed = findAndUninstallRelatedProducts(oldCode, false)
	if installed {
		fmt.Printf("Found previous product as this user")
		if checkOnly {
			fmt.Printf("Not uninstalling previous found version")
			return 1638
		}
		uninstalled := findAndUninstallRelatedProducts(oldCode, true)
		if uninstalled {
			fmt.Printf("Uninstalled previous product")
			return 1
		}
		return -2
	} else {
		installed, err := isServiceInstalled()
		fmt.Printf("isServiceInstalled: %t %s", installed, err)
		if installed {
			fmt.Printf("service installed as other user")
			return 1638
		}
		if !installed && (err == NO_ERROR || err == ERROR_SERVICE_DOES_NOT_EXIST) {
			fmt.Printf("Service not installed")
			return 0
		}
		return -2
	}
}

func main() {
	os.Exit(mainfunc())
}
