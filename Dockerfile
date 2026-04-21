FROM node:22-alpine AS frontend-builder

WORKDIR /app/admin-ui
COPY admin-ui/package.json admin-ui/pnpm-lock.yaml* ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile || pnpm install
COPY admin-ui ./
RUN pnpm build

FROM rust:1.92-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./

# 先创建空的 src 目录结构，预编译依赖（利用 Docker 层缓存）
RUN mkdir -p src admin-ui/dist && \
    echo 'fn main() {}' > src/main.rs && \
    touch admin-ui/dist/index.html && \
    cargo build --release || true && \
    rm -rf src target/release/kiro-rs target/release/deps/kiro* admin-ui/dist

# 再复制实际源码和前端产物，增量编译业务代码
COPY src ./src
COPY --from=frontend-builder /app/admin-ui/dist /app/admin-ui/dist

RUN cargo build --release

FROM alpine:3.21

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/target/release/kiro-rs /app/kiro-rs
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

VOLUME ["/app/config"]

EXPOSE 8990

ENTRYPOINT ["./docker-entrypoint.sh"]
