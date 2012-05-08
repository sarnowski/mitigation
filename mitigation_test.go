package mitigation

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

// The test will only work when running as root.
func TestActivate(t *testing.T) {
	// create temporary directory to test chrooting
	tmp, err := ioutil.TempDir("", "mitigationtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp)
	err = syscall.Chmod(tmp, 0755)
	if err != nil {
		t.Fatal("Could not change temporary directory permissions!")
	}

	// do it!
	Activate(1000, 1000, tmp)

	// verify uids
	uid := syscall.Getuid()
	if uid != 1000 {
		t.Error("Failed to change UID")
	}
	euid := syscall.Geteuid()
	if euid != 1000 {
		t.Error("Failed to change EUID")
	}

	// verify gid
	gid := syscall.Getgid()
	if gid != 1000 {
		t.Error("Failed to change GID")
	}

	// verify groups
	gids, err := syscall.Getgroups()
	if err != nil {
		t.Fatal("Could not get group list")
	}
	if len(gids) != 0 {
		t.Error("Not all groups are dropped!")
	}

	// verify directory
	dh, err := os.Open("/")
	if err != nil {
		t.Fatal("Cannot open my root directory", err)
	}
	files, err := dh.Readdir(-1)
	if err != nil {
		t.Fatal("Cannot read my root directory")
	}
	if len(files) > 0 {
		t.Error("Root not changed to empty temporary directory!")
	}
}

func ExampleActivate() {
	// prepare application execution and allocate ressources with
	// root privileges (e.g. open port 80 for an http server)
	listener, _ := net.Listen("tcp", ":80")


	// on OpenBSD, the "www" user is dedicated to serve the
	// /var/www/htdocs directory in a chrooted way
	wwwUser, _ := user.Lookup("www")
	uid, _ := strconv.Atoi(wwwUser.Uid)
	gid, _ := strconv.Atoi(wwwUser.Gid)

	// now drop all privileges and chroot!
	Activate(uid, gid, "/var/www/htdocs")


	// The application is now chrooted and only runs with "www"
	// privileges.
	http.Serve(listener, http.FileServer(http.Dir("/")))
}

func ExampleCanActivate() {
	workDir := "/var/www"

	if CanActivate() {
		// activate the mitigation and reset work directory to "/"
		Activate(67, 67, workDir)
		workDir = "/"
	} else {
		// we can handle this but log a warning
		log.Println("WARNING: Cannot activate mitigation!")
	}

	// use "workDir" to address our files
	log.Println("Working directory: ", workDir)
}
