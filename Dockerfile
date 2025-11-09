FROM node:18-slim AS builder
WORKDIR /app
COPY package.json yarn.lock* package-lock.json* ./
RUN npm install
COPY . .
COPY .env.example .env
RUN npm run prisma:generate
RUN npm run build

FROM node:18-slim AS runner
WORKDIR /app

COPY package.json yarn.lock* package-lock.json* ./
RUN npm install --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

COPY --from=builder /app/node_modules/.prisma/client ./node_modules/.prisma/client

EXPOSE 3000

CMD ["sh", "-c", "npm run prisma:migrate:prod && npm run start:prod"]