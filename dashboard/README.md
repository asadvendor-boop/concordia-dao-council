# Concordia Dashboard

Real-time proposal monitoring, evidence-chain inspection, human approval, and controlled demo scenario controls for the Concordia system.

## Stack

- **Framework:** Next.js App Router
- **Styling:** Custom CSS with glassmorphism and particle background
- **Base Path:** `/dashboard`

## Features

- Live proposal feed with state transitions and card chains
- Agent heartbeat status with online/offline indicators
- Evidence-chain verification and audit export
- Human approval shortcuts for planned proposals
- Policy guardrail visibility
- Controlled DAO proposal scenarios

## Development

```bash
npm install
npm run dev
# Open http://localhost:3000/dashboard
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `NEXT_PUBLIC_GATEWAY_URL` | Gateway API base URL | `http://localhost:8000` |
| `PROPOSAL_SIMULATOR_URL` | Proposal simulator URL, server-side only | `http://127.0.0.1:9000` |
| `CONCORDIA_LIVE_DEMO` | Enables live demo proposal triggers when set to `1` | unset |
