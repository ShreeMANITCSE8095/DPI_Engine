# DPI Platform Monorepo

This bundle combines the packet analyzer core, the Vite frontend, and the FastAPI backend in a deploy-friendly layout.

## Folder layout

- `frontend-vercel/` - React + Vite app for Vercel
- `backend-render/` - FastAPI API and C++ analyzer sources for Render
- `packet-analyzer-core/` - original standalone C++ analyzer project and samples

## Deploy targets

- Frontend: Vercel
- Backend: Render

## Environment variables

- `frontend-vercel/.env`:
  - `VITE_API_BASE_URL=https://your-render-service.onrender.com`
- `backend-render`:
  - `FRONTEND_ORIGIN=https://your-vercel-app.vercel.app`

## Notes

- The frontend now reads the API base URL from `VITE_API_BASE_URL` and falls back to `http://localhost:8000` for local development.
- The backend CORS allowlist is controlled by `FRONTEND_ORIGIN`.
- The Render backend expects the compiled binary at `backend-render/backend/build/dpi_json`.
