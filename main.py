from datetime import datetime, timedelta
from typing import Optional

import databases
import enum

import jwt
import sqlalchemy

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
from email_validator import validate_email, EmailNotValidError
from passlib.context import CryptContext
from decouple import config
from starlette.requests import Request

DATABASE_URL = f"postgresql://{config('DB_USER')}:{config('DB_PASSWORD')}@localhost:54321/clothes"

database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()


class ColorEnum(enum.Enum):
    pink = "pink"
    black = "black"
    white = "white"
    yellow = "yellow"


class SizeEnum(enum.Enum):
    xs = "xs"
    s = "s"
    m = "m"
    l = "l"
    xl = "xl"
    xxl = "xxl"


class UserRole(enum.Enum):
    super_admin = 'Super Admin'
    admin = 'Admin'
    user = 'User'


users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, unique=True),
    sqlalchemy.Column("email", sqlalchemy.String(120), unique=True),
    sqlalchemy.Column("password", sqlalchemy.String(255)),
    sqlalchemy.Column("full_name", sqlalchemy.String(200)),
    sqlalchemy.Column("phone", sqlalchemy.String(13)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, nullable=False, server_default=sqlalchemy.func.now()),
    sqlalchemy.Column(
        "last_modified_at",
        sqlalchemy.DateTime,
        nullable=False,
        server_default=sqlalchemy.func.now(),
        onupdate=sqlalchemy.func.now(),
    ),
    sqlalchemy.Column("role", sqlalchemy.Enum(UserRole), nullable=False, server_default=UserRole.user.name)
)


clothes = sqlalchemy.Table(
    "clothes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, unique=True),
    sqlalchemy.Column("name", sqlalchemy.String(120)),
    sqlalchemy.Column("color", sqlalchemy.Enum(ColorEnum), nullable=False),
    sqlalchemy.Column("size", sqlalchemy.Enum(SizeEnum), nullable=False),
    sqlalchemy.Column("photo_url", sqlalchemy.String(255)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime, nullable=False, server_default=sqlalchemy.func.now()),
    sqlalchemy.Column(
        "last_modified_at",
        sqlalchemy.DateTime,
        nullable=False,
        server_default=sqlalchemy.func.now(),
        onupdate=sqlalchemy.func.now(),
    )
)


class EmailField(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.check_email

    @classmethod
    def check_email(cls, v) -> str:
        try:
            validate_email(v)
            return v
        except EmailNotValidError:
            raise ValueError("Not a valid email address")


class BaseUser(BaseModel):
    email: EmailField
    full_name: str

    @validator("full_name")
    def check_full_name(cls, v):
        try:
            first_name, last_name = v.split()
            return v
        except Exception:
            raise ValueError("Expected first and last name, only received 1 name.")


class UserSignIn(BaseUser):
    password: str


class UserSignOut(BaseUser):
    phone: Optional[str]
    created_at: datetime
    last_modified_at: datetime


class ClothesBase(BaseModel):
    name: str
    color: str
    size: SizeEnum
    color: ColorEnum


class ClothesIn(ClothesBase):
    pass


class ClothesOut(ClothesBase):
    id: int
    created_at: datetime
    last_modified_at: datetime


app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class CustomHTTPBearer(HTTPBearer):
    async def __call__(
            self, request: Request
    ) -> Optional[HTTPAuthorizationCredentials]:
        res = await super().__call__(request)

        try:
            payload = jwt.decode(res.credentials, config("JWT_SECRET"), algorithms=["HS256"])
            user = await database.fetch_one(users.select().where(users.c.id == payload["sub"]))
            request.state.user = user
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token is expired")
        except jwt.InvalidKeyError:
            raise HTTPException(401, "Invalid token")


oauth_scheme = CustomHTTPBearer()


def is_admin(request: Request):
    user = request.state.user
    if not user or user["role"] not in (UserRole.admin, UserRole.super_admin):
        raise HTTPException(403, "You do not have permission for this resource")


def create_access_token(user):
    try:
        payload = {"sub": user["id"], "exp": datetime.utcnow() + timedelta(minutes=120)}
        return jwt.encode(payload, config("JWT_SECRET"), algorithm="HS256")
    except Exception:
        raise Exception


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.get("/clothes/", dependencies=[Depends(oauth_scheme)])
async def get_all_clothes():
    return await database.fetch_all(clothes.select())


@app.post(
    "/clothes/",
    dependencies=[Depends(oauth_scheme), Depends(is_admin)],
    response_model=ClothesOut, status_code=201
)
async def create_clothes(clothes_data: ClothesIn):
    _id = await database.execute(clothes.insert().values(**clothes_data.dict()))
    return await database.fetch_one(clothes.select(clothes.c.id == _id))


@app.post(
    "/register",
    # response_model=UserSignOut
)
async def create_user(user: UserSignIn):
    user.password = pwd_context.hash(user.password)

    query = users.insert().values(**user.dict())  # using sqlalchemy to insert new row into table

    _id = await database.execute(query)  # using database to connect to DB and execute query

    # users.c '.c' refers to column object in the table
    created_user = await database.fetch_one(users.select().where(users.c.id == _id))

    token = create_access_token(created_user)

    return token
