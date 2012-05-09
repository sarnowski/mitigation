package mitigation

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

const (
	TEST_UID = 1000
	TEST_GID = 1000

	TEST_ROUTINES_COUNT = 100
)

// The test will only work when running as root.
func TestCanActivate(t *testing.T) {
	if !CanActivate() {
		t.Fatal("Tests must run as root!")
	}
}

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

	// improve cpu usage to test for broken os implementations of setuid()
	runtime.GOMAXPROCS(2)

	// create some go routines as root to later test them
	var sync chan bool = make(chan bool)
	for i := 0; i < TEST_ROUTINES_COUNT; i++ {
		go func() {
			// no op
			sync <- true
		}()
	}
	for i := 0; i < TEST_ROUTINES_COUNT; i++ {
		<-sync
	}

	// modify environment
	err = os.Setenv("malicous_env", "bad string")
	if err != nil {
		t.Fatal("Cannot setup environment variables!")
	}
	if len(os.Environ()) == 0 {
		t.Fatal("Environ() or Setenv() are broken!")
	}

	// do it!
	Activate(TEST_UID, TEST_GID, tmp)

	// verify uids
	uid := syscall.Getuid()
	if uid != TEST_UID {
		t.Error("Failed to change UID")
	}
	euid := syscall.Geteuid()
	if euid != TEST_UID {
		t.Error("Failed to change EUID")
	}

	// verify gid
	gid := syscall.Getgid()
	if gid != TEST_GID {
		t.Error("Failed to change GID")
	}

	// verify groups
	gids, err := syscall.Getgroups()
	if err != nil {
		t.Fatal("Could not get group list")
	}
	if len(gids) > 1 {
		t.Error("Not all groups are dropped!")
	} else if len(gids) == 1 {
		if gids[0] != TEST_GID {
			t.Error("Not all foreign groups are dropped!")
		}
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

	// verify environment
	if len(os.Environ()) > 0 {
		t.Error("Environment variables found!")
	}

	// test setuid() behaviour
	var results chan int = make(chan int)

	// start multiple goroutines, in a good OS, all all routines
	// should be switched to the new user
	for i := 0; i < TEST_ROUTINES_COUNT; i++ {
		go func() {
			results <- syscall.Getuid()
		}()
	}

	// check the results
	for i := 0; i < TEST_ROUTINES_COUNT; i++ {
		uid := <-results
		if uid != TEST_UID {
			t.Error("false uid: ", uid, " (you are using an unsafe os, read the package documentation!)")
			break
		}
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
