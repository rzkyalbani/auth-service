FROM node:18-alpine AS builder

WORKDIR /app

COPY package.json yarn.lock* package-lock.json* ./

RUN npm install --omit=dev

COPY . .

COPY .env.example .env
RUN npm run prisma:generate

RUN npm run build

FROM node:18-alpine AS runner

WORKDIR /app

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

COPY --from=builder /app/prisma ./prisma

EXPOSE 3000

CMD ["sh", "-c", "npm run prisma:migrate && npm run start:prod"]