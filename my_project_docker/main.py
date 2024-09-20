import datetime as dt
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.templating import Jinja2Templates
from jose import JWTError, jwt
from pydantic import BaseModel
from rich import inspect, print
from rich.console import Console

from sqlalchemy import create_engine

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import Column, Integer, String

from sqlalchemy.orm import sessionmaker

from sqlalchemy.orm import Session

from fastapi.responses import JSONResponse, FileResponse

from fastapi import Depends, FastAPI, Body


console = Console()

# строка подключения к БД
SQLALCHEMY_DATABASE_URL = 'postgresql://postgres:123@localhost/my_db_notes'

# создание движка
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# создаем базовый класс для моделей
class Base(DeclarativeBase): pass


# создаем модели, объекты которых будут храниться в бд
class Users(Base):
    __tablename__ = "users"

    id_users = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    password = Column(String, )

class Notes(Base):
    __tablename__ = "notes"

    id_users = Column(Integer)
    id_notes = Column(Integer, primary_key=True, index=True)
    text = Column(String, )

# создаем сессии подключения к бд
SessionLocal = sessionmaker(autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_users = SessionLocal()
db_users.query(Users)

# получение всех объектов db_users
people = db_users.query(Users).all()

# --------------------------------------------------------------------------
# Models and Data
# --------------------------------------------------------------------------
class User(BaseModel):
    id_users: int
    username: str
    password: str


def get_user(username: str):
    user = [user for user in people if user.username == username]
    if user:
        return user[0]
    return None

# --------------------------------------------------------------------------
# Setup FastAPI
# --------------------------------------------------------------------------
class Settings:
    SECRET_KEY: str = "secret-key"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30  # in mins
    COOKIE_NAME = "access_token"

app = FastAPI()
templates = Jinja2Templates(directory="templates")
settings = Settings()

# --------------------------------------------------------------------------
# Authentication logic
# --------------------------------------------------------------------------
class OAuth2PasswordBearerWithCookie(OAuth2):
    """
 This class is taken directly from FastAPI:
 https://github.com/tiangolo/fastapi/blob/26f725d259c5dbe3654f221e608b14412c6b40da/fastapi/security/oauth2.py#L140-L171

 The only change made is that authentication is taken from a cookie
 instead of from the header!
 """

    def __init__(
            self,
            tokenUrl: str,
            scheme_name: Optional[str] = None,
            scopes: Optional[Dict[str, str]] = None,
            description: Optional[str] = None,
            auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        # IMPORTANT: this is the line that differs from FastAPI. Here we use
        # `request.cookies.get(settings.COOKIE_NAME)` instead of
        # `request.headers.get("Authorization")`
        authorization: str = request.cookies.get(settings.COOKIE_NAME)
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="token")


def create_access_token(data: Dict) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def authenticate_user(username: str, plain_password: str) -> User:
    user = get_user(username)
    if not user:
        return False
    if not (plain_password == user.password):
        return False
    return user


def decode_token(token: str) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials."
    )
    token = token.removeprefix("Bearer").strip()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        print(e)
        raise credentials_exception

    user = get_user(username)
    return user


def get_current_user_from_token(token: str = Depends(oauth2_scheme)) -> User:
    """
 Get the current user from the cookies in a request.

 Use this function when you want to lock down a route so that only
 authenticated users can see access the route.
 """
    user = decode_token(token)
    return user


def get_current_user_from_cookie(request: Request) -> User:
    """
 Get the current user from the cookies in a request.

 Use this function from inside other routes to get the current user. Good
 for views that should work for both logged in, and not logged in users.
 """
    token = request.cookies.get(settings.COOKIE_NAME)
    user = decode_token(token)
    return user


@app.post("token")
def login_for_access_token(
        response: Response,
        form_data: OAuth2PasswordRequestForm = Depends()
) -> Dict[str, str]:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"username": user.username})
    # Set an HttpOnly cookie in the response. `httponly=True` prevents
    # JavaScript from reading the cookie.
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=f"Bearer {access_token}",
        httponly=True
    )
    return {settings.COOKIE_NAME: access_token, "token_type": "bearer"}


# --------------------------------------------------------------------------
# Home Page
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    try:
        user = get_current_user_from_cookie(request)
    except:
        user = None
    context = {
        "user": user,
        "request": request,
    }
    return templates.TemplateResponse("index.html", context)


# --------------------------------------------------------------------------
# Notes Page
# --------------------------------------------------------------------------
# A notes page that only logged in users can access.
@app.get("/notes", response_class=HTMLResponse)
def index(request: Request, user: User = Depends(get_current_user_from_token)):
    context = {
        "user": user,
        "request": request
    }
    return templates.TemplateResponse("notes.html", context)


# --------------------------------------------------------------------------
# Login - GET
# --------------------------------------------------------------------------
@app.get("/auth/login", response_class=HTMLResponse)
def login_get(request: Request):
    context = {
        "request": request,
    }
    return templates.TemplateResponse("login.html", context)


# --------------------------------------------------------------------------
# Login - POST
# --------------------------------------------------------------------------
class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.errors: List = []
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def load_data(self):
        form = await self.request.form()
        self.username = form.get("username")
        self.password = form.get("password")

    async def is_valid(self):
        if not self.username or not (self.username.__contains__("@")):
            self.errors.append("Email is required")
        if not self.password or not len(self.password) >= 4:
            self.errors.append("A valid password is required")
        if not self.errors:
            return True
        return False


@app.post("/auth/login", response_class=HTMLResponse)
async def login_post(request: Request):
    form = LoginForm(request)
    await form.load_data()
    if await form.is_valid():
        try:
            response = RedirectResponse("/", status.HTTP_302_FOUND)
            login_for_access_token(response=response, form_data=form)
            form.__dict__.update(msg="Login Successful!")
            console.log("[green]Login successful!!!!")
            return response
        except HTTPException:
            form.__dict__.update(msg="")
            form.__dict__.get("errors").append("Incorrect Email or Password")
            return templates.TemplateResponse("login.html", form.__dict__)
    return templates.TemplateResponse("login.html", form.__dict__)


# --------------------------------------------------------------------------
# Logout
# --------------------------------------------------------------------------
@app.get("/auth/logout", response_class=HTMLResponse)
def login_get():
    response = RedirectResponse(url="/")
    response.delete_cookie(settings.COOKIE_NAME)
    return response

@app.get("/notes/all")
def get_notes(db: Session = Depends(get_db), user: User = Depends(get_current_user_from_token)):
    note = db.query(Notes).all()
    notes = db.query(Notes).filter_by(id_users=user.id_users).all()
    return notes



@app.get("/notes/all/{id}")
def get_note(id, db: Session = Depends(get_db)):
    # получаем пользователя по id
    note = db.query(Notes).filter(Notes.id_notes == id).first()
    # если не найден, отправляем статусный код и сообщение об ошибке
    if note == None:
        return JSONResponse(status_code=404, content={"message": "Заметка не найдена"})
    # если пользователь найден, отправляем его
    return note



@app.post("/notes/all")
def create_person(data=Body(), db: Session = Depends(get_db)):
    print(data)
    note = Notes(id_users=data["id_users"], id_notes=data["id_notes"], text=data["name"])
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@app.put("/notes/all")
def edit_person(data=Body(), db: Session = Depends(get_db)):
    # получаем заметку по id
    print(data)
    note = db.query(Notes).filter(Notes.id_notes == data["id_notes"]).first()
    # если не найден, отправляем статусный код и сообщение об ошибке
    if note == None:
        return JSONResponse(status_code=404, content={"message": "Заметка не найдена"})
    # если заметка найдена, изменяем ее данные и отправляем обратно клиенту
    note.text = data["text"]
    #note.name = speller.spelled(data["name"])
    db.commit()  # сохраняем изменения
    db.refresh(note)
    return note


