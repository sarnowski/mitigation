/*
Package mitigation provides the possibility to prevent damage through bugs or exploits.

The package uses multiple techniques to mitigate damage:
	- privilege revocation: switch to an unprivileged user
	- chroot jail: restrict filesystem access
	- defined environment: reset all environment variables

The following prerequisites are nessecary:
	- The application must run as root
	- You need to provide a valid user id
	- You need to provide a valid group id
	- You need to provide an existing path

Activate() will not return any error. It will panic as soon as anything
goes wrong because there is no good way to recover. To provide a sensible
fallback you can use the CanActivate() function.

WARNING: Windows is not supported. Windows has no equivalents for the used
techniques.

WARNING: Linux is not POSIX compatible and therefor setuid() only changes the
user ID of the current thread. At the time, there is no way to safely use
this within go as there may already be other threads spawned at the time
this library is called. More about this issue here:
	http://code.google.com/p/go/issues/detail?id=1435
	http://groups.google.com/group/golang-nuts/browse_thread/thread/059597aafdd84a0e

The following table summarizes the behaviours:
	openbsd: safe
	freebsd: safe
	darwin:  safe
	linux:   unsafe
	windows: not supported

*/
package mitigation

import (
	"os"
	"runtime"
	"syscall"
)

// Checks if it is possible to activate the mitigation.
func CanActivate() bool {
	if runtime.GOOS == "windows" {
		return false
	}

	uid := syscall.Getuid()
	return uid == 0
}

// Activates the mitigation measurements.
func Activate(uid int, gid int, path string) {
	if !CanActivate() {
		panic("Cannot activate mitigation measurements!")
	}

	// chroot directory
	err := syscall.Chroot(path)
	if err != nil {
		panic(err)
	}

	// change directory to new /
	err = syscall.Chdir("/")
	if err != nil {
		panic(err)
	}

	// drop all other groups
	err = syscall.Setgroups([]int{})
	if err != nil {
		panic(err)
	}

	// verify the empty group list
	gids, err := syscall.Getgroups()
	if err != nil {
		panic("Could not read groups!")
	}
	if len(gids) > 1 {
		panic("Could not drop groups!")
	} else if len(gids) == 1 {
		if gids[0] != gid {
			panic("Could not drop foreign groups!")
		}
	}

	// change group
	err = syscall.Setgid(gid)
	if err != nil {
		panic(err)
	}

	// verify the group change
	ngid := syscall.Getgid()
	if ngid != gid {
		panic("Could not change group id!")
	}

	// change user
	err = syscall.Setuid(uid)
	if err != nil {
		panic(err)
	}

	// verify the user change
	nuid := syscall.Getuid()
	if nuid != uid {
		panic("Could not change user id!")
	}

	// now drop all environment variables
	os.Clearenv()
}
