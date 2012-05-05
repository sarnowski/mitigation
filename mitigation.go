/*
Package mitigation provides the possibility to prevent system damage.

The package uses multiple techniques to mitigate damage:
	- privilege revocation: switch to an unprivileged user
	- chroot jail: hide the real filesystem
	- defined environment: reset all environment variables

The following prerequisites are nessecary:
	- The application must run as root
	- You need to provide a valid user id
	- You need to provide a valid group id
	- You need to provide an existing path

Activate() will not return any error. It will panic as soon as anything
goes wrong because there is no good way to recover. To provide a sensible
fallback you can use the CanActivate() function.
*/
package mitigation

import (
	"os"
	"syscall"
)

// Checks if it is possible to activate the mitigation.
func CanActivate() bool {
	uid := syscall.Getuid()
	return uid == 0
}

// Activates the mitigation measurements.
func Activate(uid int, gid int, path string) {
	if !CanActivate() {
		panic("Cannot revoke privileges!")
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
	if len(gids) != 0 {
		panic("Could not drop groups!")
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
