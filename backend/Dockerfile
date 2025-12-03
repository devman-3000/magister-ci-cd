# syntax=docker/dockerfile:1.7
# Dockerfile.backend
# ====== Builder stage ======
# go.mod pins toolchain go1.24.x, so use the matching Go image to avoid toolchain downloads
FROM golang:1.24-alpine AS build
WORKDIR /app/backend
ENV GOTOOLCHAIN=auto
ENV GOMODCACHE=/go/pkg/mod
ENV GOCACHE=/root/.cache/go-build

# CGO потрібен для sqlite3; тягнемо компілятор і sqlite headers
RUN apk add --no-cache build-base sqlite-dev

# Кешуємо залежності
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Копіюємо код бекенду (білд виконуй з каталогу backend/)
COPY . .

# Релізний білд
ENV GIN_MODE=release
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /bin/server ./main.go

# ====== Runtime stage ======
FROM alpine:3.20
RUN apk add --no-cache ca-certificates sqlite-libs tzdata \
  && adduser -S -D -H appuser

# Дуже важливо: робоча директорія /app/backend,
# щоб відносний шлях ../database/app.db вказував на /app/database/app.db
WORKDIR /app/backend
RUN mkdir -p /app/database

# Бінарник
COPY --from=build /bin/server /app/server
# (необов'язково) Якщо маєш початковий app.db у репо, можеш додати:
# COPY ../database/app.db /app/database/app.db

ENV GIN_MODE=release
EXPOSE 8080
# Збереження БД між перезапусками (за бажанням підмонтуй том)
VOLUME ["/app/database"]

USER appuser
CMD ["/app/server"]
