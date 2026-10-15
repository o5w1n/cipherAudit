# OpenSSL 3.5+ with hybrid ML-KEM groups (X25519MLKEM768).
FROM alpine:3.22
RUN apk add --no-cache openssl \
 && mkdir /certs \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -keyout /certs/key.pem -out /certs/cert.pem
EXPOSE 443
CMD ["openssl", "s_server", "-accept", "443", "-cert", "/certs/cert.pem", "-key", "/certs/key.pem", \
     "-groups", "X25519MLKEM768:X25519:P-256", "-www"]
