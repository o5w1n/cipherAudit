# nginx on OpenSSL 3.5+ (hybrid ML-KEM groups). nginx rather than `openssl s_server`, which serves one
# connection at a time: a single idle client made every probe time out ("no TLS service").
FROM alpine:3.22
RUN apk add --no-cache nginx openssl \
 && mkdir /certs \
 && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 825 \
      -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -keyout /certs/key.pem -out /certs/cert.pem
COPY nginx.conf /etc/nginx/http.d/default.conf
EXPOSE 443 4443
CMD ["nginx", "-g", "daemon off;"]
