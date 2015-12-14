export GOPATH:=$(abs_top_srcdir)/Godeps/_workspace:$(GOPATH)

all-local: build-cli build-daemon
clean-local:
	-rm -f citadm citd
install-exec-local: 
	$(INSTALL_PROGRAM) citadm $(bindir)
	$(INSTALL_PROGRAM) citd $(bindir)

build-cli:
	go build citadm.go
build-daemon:
	go build citd.go
