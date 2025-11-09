FROM node:18-slim AS builder
WORKDIR /app

COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM node:18-slim AS runner
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

RUN apt-get update -y && apt-get install -y openssl

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

RUN npx prisma generate

EXPOSE 3000
CMD ["sh", "-c", "npm run prisma:migrate:prod && npm run start:prod"]
