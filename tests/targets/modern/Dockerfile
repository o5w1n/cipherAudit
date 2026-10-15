FROM nginx:1.27-alpine
# Local test CA + server certificate, so scans can run with --ca-file certs/modern-ca.pem and see a trusted chain.
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/certs && cd /etc/nginx/certs \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
      -subj "/CN=cipherAudit Test CA" -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -keyout ca.key -out ca.pem \
 && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
      -keyout key.pem -out server.csr \
 && printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n" > ext.cnf \
 && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 \
      -extfile ext.cnf -out cert.pem \
 && rm ca.key server.csr ext.cnf
COPY nginx.conf /etc/nginx/conf.d/default.conf
