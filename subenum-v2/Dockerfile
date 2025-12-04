FROM golang:1.25-alpine AS builder

RUN apk add --no-cache \
	git \
	build-base \
	libpcap-dev \
	cargo \
	bash \
	perl

ENV CGO_ENABLED=1

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
	go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
	go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
	go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
	go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
	go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
	go install -v github.com/tomnomnom/assetfinder@latest

RUN git clone https://github.com/Findomain/Findomain.git /tmp/findomain && \
	cd /tmp/findomain && \
	cargo build --release

RUN git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && \
	cd /tmp/massdns && \
	make

FROM python:3.12-alpine

RUN apk add --no-cache \
	ca-certificates \
	libcap \
	libpcap \
	libgcc \
	libstdc++ \
	bash \
	perl \
	git \
	build-base

COPY --from=builder /go/bin/* /usr/local/bin/
COPY --from=builder /tmp/findomain/target/release/findomain /usr/local/bin/
COPY --from=builder /tmp/massdns/bin/massdns /usr/local/bin/

RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/local/bin/naabu

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python3"]
CMD ["src/subenum.py"]
