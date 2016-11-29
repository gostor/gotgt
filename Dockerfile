FROM debian:jessie
MAINTAINER Lei Xue <carmark.dlut@gmail.com>

# setup golang environment
ENV GOLANG_VERSION 1.7.3
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 508028aac0654e993564b6e2014bf2d4a9751e3b286661b0b0040046cf18028e

RUN apt-get update && apt-get install -y curl automake gcc make
RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
	&& echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf golang.tar.gz \
	&& rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

RUN mkdir -p /go/src/github.com/gostor/gotgt
ADD . /go/src/github.com/gostor/gotgt
WORKDIR ${GOPATH}/src/github.com/gostor/gotgt
RUN ./autogen.sh
RUN ./configure
RUN make

EXPOSE 23457
EXPOSE 3260
CMD ["./gotgt", "daemon"]

RUN apt-get purge -y curl automake gcc make
RUN apt-get autoremove -y
