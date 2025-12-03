# Stage 1 — build
FROM node:20-alpine AS build
WORKDIR /app
ARG APP_ENV=stage
ENV VITE_APP_ENV=${APP_ENV}
COPY package.json package-lock.json* yarn.lock* pnpm-lock.yaml* ./
RUN npm ci || yarn install || pnpm install
COPY . .
RUN npm run build || yarn build || pnpm build

# Stage 2 — serve static
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
