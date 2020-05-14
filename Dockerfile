FROM docker.io/library/golang:1.14.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/state-writer
WORKDIR /go/src/github.com/cilium/state-writer
RUN CGO_ENABLED=0 GOOS=linux go build

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/state-writer/state-writer /usr/bin/state-writer
WORKDIR /
CMD ["/usr/bin/state-writer"]
