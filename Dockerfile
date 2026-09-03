# Build multi-stage. Contexte de build = racine du dépôt (pas server/) :
# ce conteneur sert désormais aussi le frontend et le module WASM (étape 9
# + suite), pas seulement l'API — il a donc besoin de core/, wasm/ et web/
# en plus de server/. Décision prise en anticipation d'un déploiement VPS :
# un seul service, une seule origine, le client n'a plus à connaître ou
# saisir une URL d'API séparée (voir server/src/main.rs).

# --- Stage 1 : compilation du module WASM (core/ + wasm/) ---
FROM rust:1.98-slim AS wasm-builder
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown \
    && curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
WORKDIR /build
COPY core ./core
COPY wasm ./wasm
RUN cd wasm && wasm-pack build --target web --release

# --- Stage 2 : compilation du serveur (server/, ne dépend pas de core/) ---
# perl/make/gcc : nécessaires pour compiler OpenSSL vendored (dépendance de
# webauthn-rs, étape 9+ — auth réseau par YubiKey). Vendored plutôt que la
# libssl du système : évite de dépendre d'un paquet -dev dont la version
# varie selon l'image de base, au prix d'un openssl compilé depuis les
# sources à chaque build (plus lent, mais reproductible).
FROM rust:1.98-slim AS server-builder
RUN apt-get update && apt-get install -y --no-install-recommends perl make gcc \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY server/Cargo.toml server/Cargo.lock* ./
COPY server/src ./src
RUN cargo build --release

# --- Stage 3 : image runtime minimale ---
# debian-slim, pas distroless : plus simple à déboguer via `docker exec`
# pendant le développement local. La minimisation d'image relève
# explicitement de la passe de durcissement du PRD §10, pas de maintenant.
# trixie (Debian 13), pas bookworm : doit matcher la base de `rust:1.98-slim`
# (elle-même trixie) pour que la glibc du runtime soit au moins aussi récente
# que celle utilisée à la compilation — sinon le binaire échoue au lancement
# (`GLIBC_2.38' not found`, symbole introduit par le lien vers OpenSSL
# vendored/webauthn-rs, absent de la glibc plus ancienne de bookworm).
FROM debian:trixie-slim
RUN useradd --system --create-home --home-dir /home/vaultkey vaultkey
WORKDIR /app
COPY --from=server-builder /build/target/release/vaultkey-server /usr/local/bin/vaultkey-server
COPY web ./web
COPY --from=wasm-builder /build/wasm/pkg ./wasm/pkg
COPY sw.js ./sw.js
RUN mkdir -p /data && chown vaultkey:vaultkey /data
USER vaultkey
ENV DATA_DIR=/data
ENV STATIC_DIR=/app
ENV PORT=8080
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/vaultkey-server"]
