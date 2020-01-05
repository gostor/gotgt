FROM debian:jessie
MAINTAINER Lei Xue <carmark.dlut@gmail.com>

COPY _output/cmd/bin/gotgt /bin
EXPOSE 23457
EXPOSE 3260
CMD ["/bin/gotgt", "daemon"]