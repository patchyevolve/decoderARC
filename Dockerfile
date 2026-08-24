FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1 AS build
RUN apk add --no-cache clang linux-headers curl-dev
WORKDIR /build
COPY include/ include/
COPY tools/ids_production.cpp tools/
RUN clang++ -std=c++17 -O2 -Iinclude tools/ids_production.cpp -o ids_production -lpthread -lcurl

FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
RUN apk add --no-cache libstdc++ && adduser -D idsuser && mkdir -p /var/lib/ids /etc/ids && chown -R idsuser:idsuser /var/lib/ids /etc/ids
COPY --from=build /build/ids_production /usr/local/bin/
COPY tools/ids_production.conf /etc/ids/ids.conf
EXPOSE 9102
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost:9102/metrics || exit 1
USER idsuser
ENTRYPOINT ["ids_production"]
CMD ["eth0"]
