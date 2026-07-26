FROM node:20-bookworm-slim

WORKDIR /app

ARG NEXT_PUBLIC_GATEWAY_URL=""
ARG NEXT_PUBLIC_CONCORDIA_MODE="reviewer"
ARG NEXT_PUBLIC_CSPR_CLICK_APP_ID="csprclick-template"

ENV NEXT_TELEMETRY_DISABLED=1 \
    NEXT_PUBLIC_GATEWAY_URL="${NEXT_PUBLIC_GATEWAY_URL}" \
    NEXT_PUBLIC_CONCORDIA_MODE="${NEXT_PUBLIC_CONCORDIA_MODE}" \
    NEXT_PUBLIC_CSPR_CLICK_APP_ID="${NEXT_PUBLIC_CSPR_CLICK_APP_ID}"

COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci

COPY dashboard/ ./
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start", "--", "-H", "0.0.0.0", "-p", "3000"]
