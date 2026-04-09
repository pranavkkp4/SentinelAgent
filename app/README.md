# SentinelAgent Frontend

This folder contains the React + TypeScript + Vite frontend for SentinelAgent. It talks to the FastAPI backend in the sibling `sentinel-agent/backend` project.

## Requirements

- Node.js `20.19.0` or newer
- npm
- A running SentinelAgent backend, usually on `http://localhost:8000`

## Setup

1. Open a terminal in the `app/` folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a local `.env` file in `app/` and set the backend URL:
   ```bash
   VITE_API_BASE_URL=http://localhost:8000
   ```
4. Start the backend API in `sentinel-agent/backend`.
5. Start the frontend:
   ```bash
   npm run dev
   ```
6. Open the Vite URL printed in the terminal, usually `http://localhost:5173`.

## Scripts

- `npm run dev` starts the Vite dev server.
- `npm run build` type-checks and produces a production bundle in `dist/`.
- `npm run preview` serves the production build locally.
- `npm run lint` runs ESLint.
- `npm run typecheck` runs the TypeScript project build without emitting files.
- `npm run check` runs type-checking and linting together.

## Environment

The frontend reads one required environment variable:

- `VITE_API_BASE_URL` - base URL of the SentinelAgent API. If unset, the app falls back to `http://localhost:8000`.

## Troubleshooting

- If the demo or metrics sections are empty, confirm the backend is running and that `VITE_API_BASE_URL` points to it.
- If browser requests fail, make sure the backend CORS settings allow the frontend origin.
- If `npm run build` fails with TypeScript or ESLint errors, run `npm install` again inside `app/`.
- If you deploy the frontend, set `VITE_API_BASE_URL` before building so the bundled app points to the deployed backend instead of localhost.

## Notes

- The frontend data shown in the attack demo and metrics dashboard is fetched from the backend API.
- No private datasets are bundled in this folder; the sample attack payloads are synthetic demo content.
