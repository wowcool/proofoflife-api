# Proof of Life API Server

Cryptographic proof verification API for proofoflife.io

## Overview

This API server provides verification endpoints for Proof of Life - a blockchain-based proof system that creates immutable, verifiable records of presence using WorldChain.

## Endpoints

### `GET /api/public/proofoflife/:proofId`
Renders a public HTML page displaying proof details including:
- Photo (if attached)
- Location (What3Words, coordinates)
- Verifiable hash
- Blockchain timestamp
- Device attestation status
- "How This Proof Works" explanation

### `GET /api/public/proofoflife/:proofId/data`
Returns JSON data for programmatic access.

### `GET /health`
Health check endpoint.

## Environment Variables

- `DATABASE_URL` - Neon PostgreSQL connection string
- `PORT` - Server port (default: 5000)
- `NODE_ENV` - Environment (development/production)

## Development

```bash
npm install
npm run dev
```

## Production Build

```bash
npm run build
npm start
```

## Deployment

Deployed on Fly.io at `proof.proofoflife.io`

## Technology

- Node.js + Express
- Drizzle ORM + Neon PostgreSQL
- WorldChain Blockchain
- IPFS via Pinata
