# Стенд openssl-basic: openssl s_server из пакетов Alpine.
# Ключ и сертификат генерируются при старте контейнера в /tmp/stand и в образ
# не попадают.
FROM alpine:3

RUN apk add --no-cache bash openssl

WORKDIR /stand
COPY gen-cert.sh run.sh ./

# Внутри контейнера сервер слушает все интерфейсы: иначе проброс порта не
# работает. Наружу порт публикуется только на 127.0.0.1 (tests/docker-compose.yml).
ENV STAND_BIND=0.0.0.0 \
    STAND_PORT=4433 \
    STAND_TMP=/tmp/stand

EXPOSE 4433
USER nobody

ENTRYPOINT ["/stand/run.sh"]
