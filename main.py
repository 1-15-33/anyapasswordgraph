from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from metrics import analyze

# 1. Создаём лимитер (считает по IP)
limiter = Limiter(key_func=get_remote_address, default_limits=["20/minute"])

# 2. Отключаем docs и redoc (чтобы не светить структуру API)
app = FastAPI(
    title="AnyaPasswordGraph",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# 3. Подключаем лимитер к приложению
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

templates = Jinja2Templates(directory="templates")


class AnalyzeIn(BaseModel):
    password: str = ""


# 4. Middleware для Security Headers (защитные заголовки)
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Запрещаем браузеру угадывать тип контента (MIME-sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Запрещаем встраивать сайт в iframe (защита от кликджекинга)
    response.headers["X-Frame-Options"] = "DENY"
    # Включаем защиту XSS в старых браузерах
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Заставляем использовать HTTPS (HSTS) — Render это поддерживает
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


# 5. Ограничиваем /analyze: 10 запросов в минуту с одного IP
@app.post("/analyze")
@limiter.limit("10/minute")
def analyze_endpoint(request: Request, payload: AnalyzeIn):
    if not payload.password:
        return JSONResponse({"error": "Пустой пароль"}, status_code=400)
    return analyze(payload.password)