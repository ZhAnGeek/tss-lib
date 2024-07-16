FROM golang:1.21


RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.31.0
RUN apt update && apt install -y unzip
RUN PB_REL="https://github.com/protocolbuffers/protobuf/releases" && \
curl -LO $PB_REL/download/v25.3/protoc-25.3-linux-x86_64.zip && \
unzip protoc-25.3-linux-x86_64.zip -d /local
ENV PATH="$PATH:/local/bin"
WORKDIR /

CMD [ "protoc", "--version"]