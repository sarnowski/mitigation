package main

import (
	"flag"
	"net"
	"net/http"
	"os/user"
	"strconv"

	"github.com/sarnowski/mitigation"
)

var (
	listen = flag.String("listen", ":80", "[address]:port to serve http")
	wwwUser = flag.String("user", "www", "unprivileged user to switch to")
	htdocs = flag.String("htdocs", "/var/www/htdocs", "directory to serve")
)

func main() {
	// read command line arguments
	flag.Parse()

	// open the port, this may be a "root-port" (< 1024)
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}

	// lookup the user to get his uid and gid
	wwwUserData, err := user.Lookup(*wwwUser)
	if err != nil {
		panic(err)
	}
	uid, _ := strconv.Atoi(wwwUserData.Uid)
	gid, _ := strconv.Atoi(wwwUserData.Gid)

	// now drop all privileges and jail us into the directory
	mitigation.Activate(uid, gid, *htdocs)

	// now serve http over the already opened listener
	// it isn't possible to open a port < 1024 anymore
	//
	// also serve "/" as we are chroot'ed to the destination
	// directory already
	http.Serve(listener, http.FileServer(http.Dir("/")))

	// now open your browser and have fun!

	// for security resons, the "htdocs" directory and all its
	// content should NOT be owned by the "user" we switched to
	//
	// in case of an exploit, the exploiter would only be able
	// to read the "htdocs" content but cannot modify anything
	// or access anything else on the system. His best bet would
	// be a user-accessible kernel exploit or to exploit some
	// ressources we opened (e.g. a database connection)
}
