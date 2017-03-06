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

var ofile *os.File

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
		fmt.Fprintf(ofile, "Failed to open SC Manager %s\n", err)
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
		fmt.Fprintf(ofile, "Failed to open Service %s\n", err)
	}

	if hSCM != uintptr(0) {
		closeServiceHandle.Call(uintptr(hSCM))
	}
	return
}

const ERROR_NO_MORE_DATA syscall.Errno = 259
const cchGUID int = 38

func convert_windows_string(winput []uint16) string {
	var retstring string
	for i := 0; i < len(winput); i++ {
		if winput[i] == 0 {
			break
		}
		retstring += string(rune(winput[i]))
	}
	return retstring
}
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
			} else {
				pc := convert_windows_string(buf)
				fmt.Fprintf(ofile, "Found code: %s", pc)
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
		fmt.Fprintf(ofile, "Missing Parameter")
		return -1
	}

	installed := findAndUninstallRelatedProducts(newCode, false)
	if installed {
		fmt.Fprintf(ofile, "Found current product installed.")
		return 0
	}
	installed = findAndUninstallRelatedProducts(oldCode, false)
	if installed {
		fmt.Fprintf(ofile, "Found previous product as this user")
		if checkOnly {
			fmt.Fprintf(ofile, "Not uninstalling previous found version")
			return 1635
		}
		uninstalled := findAndUninstallRelatedProducts(oldCode, true)
		if uninstalled {
			fmt.Fprintf(ofile, "Uninstalled previous product")
			return 1
		}
		return -2
	} else {
		installed, err := isServiceInstalled()
		fmt.Fprintf(ofile, "isServiceInstalled: %t %s", installed, err)
		if installed {
			fmt.Fprintf(ofile, "service installed as other user")
			return 1636
		}
		if !installed && (err == NO_ERROR || err == ERROR_SERVICE_DOES_NOT_EXIST) {
			fmt.Fprintf(ofile, "Service not installed")
			return 0
		}
		return -2
	}
}

func main() {
	newfile, err := os.Create("c:\\tmp\\msidel.txt")
	if err != nil {
		fmt.Printf("Error: %s", err)
	}
	ofile = newfile
	defer ofile.Close()
	os.Exit(mainfunc())
}
