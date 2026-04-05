# Flask API (MongoDB)

## 1) Setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## 2) Environment

Create `.env` in `backend/`:

```env
MONGODB_URI=mongodb://localhost:27017
MONGODB_DB=heritage_hues
CORS_ORIGINS=http://localhost:5173,http://localhost:5174
```

## 3) Run API

```bash
python app.py
```

API base URL: `http://localhost:5000`

## Endpoints

- `GET /api/health`
- `GET /api/products`
- `GET /api/products/<slug>`
- `POST /api/admin/products`
- `PUT /api/admin/products/<product_id>`
- `DELETE /api/admin/products/<product_id>`
