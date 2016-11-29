export GOPATH:=$(abs_top_srcdir)/Godeps/_workspace:$(GOPATH)

all-local: build
clean-local:
	-rm -f gotgt
install-exec-local: 
	$(INSTALL_PROGRAM) gotgt $(bindir)

build:
	go build gotgt.go
