FROM       arken/gom-base
MAINTAINER Damien Metzler <dmetzler@nuxeo.com>

RUN go get github.com/ruhmesmeile/gogeta
WORKDIR /usr/local/go/src/github.com/ruhmesmeile/gogeta
RUN git checkout master
RUN gom install
RUN gom test
RUN gom build

EXPOSE 7777
ENTRYPOINT ["/usr/local/go/src/github.com/ruhmesmeile/gogeta/gogeta", "-etcdAddress", "http://172.17.42.1:4001", "-alsologtostderr=true"]
