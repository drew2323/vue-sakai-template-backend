from fastapi import FastAPI, Depends, HTTPException, status, Path
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Field, Session, SQLModel, create_engine, select, Relationship
from typing import Optional, List, Callable
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from google.oauth2 import id_token
from google.auth.transport import requests
from enum import Enum
import uuid
import uvicorn
from pydantic import BaseModel
from rich import print

DATABASE_URL = "sqlite:///./test.sqlite"
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})

app = FastAPI()

# Allowed origins (Vue front-end URL)
origins = [
    "http://localhost:5150",  # Front-end URL
]

# Adding the CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allow Vue frontend origin
    allow_credentials=True,  # Allow cookies to be sent with requests (if needed)
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers (including Authorization for JWTs)
)


SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 0.1

pwd_context = CryptContext(schemes=["des_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

class TenantRole(str, Enum):
    ADMIN = "admin"
    LEVEL1 = "level1"
    LEVEL2 = "level2"

class AppWideRole(str, Enum):
    STANDARD = "standard"
    SUPERUSER = "superuser"

class Tenant(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(index=True)
    user_created_id: uuid.UUID = Field(foreign_key="user.id")
    date_created: datetime = Field(default_factory=datetime.utcnow)

    #relationship attributtes - allow us to use Objects(instead of just ids)
    user_created: "User" = Relationship(back_populates="created_tenants")
    tenant_access: List["TenantAccess"] = Relationship(back_populates="tenant")

class TenantAccess(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id")
    tenant_id: uuid.UUID = Field(foreign_key="tenant.id")
    role: TenantRole

    user: "User" = Relationship(back_populates="tenant_access")
    tenant: Tenant = Relationship(back_populates="tenant_access")

class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: Optional[str] = Field(default=None, unique=True)
    full_name: Optional[str] = None
    hashed_password: str
    disabled: bool = False
    app_role: AppWideRole = AppWideRole.STANDARD

    tenant_access: List[TenantAccess] = Relationship(back_populates="user")
    created_tenants: List[Tenant] = Relationship(back_populates="user_created")

class Config:
    arbitrary_types_allowed = True

class TenantWithRole(BaseModel):
    id: uuid.UUID
    name: str
    role: TenantRole
    date_created: datetime

    class Config:
        use_enum_values = True

class UserWithTenant(BaseModel):
    id: uuid.UUID
    username: str
    email: Optional[str]
    full_name: Optional[str]
    app_role: AppWideRole
    tenant_access: List[TenantWithRole]

    class Config:
        use_enum_values = True

class Token(SQLModel):
    access_token: str
    token_type: str

class TokenData(SQLModel):
    username: Optional[str] = None
    tenant_access: Optional[List[TenantAccess]] = None
    app_role: Optional[AppWideRole] = None

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_user(session: Session, username: str) -> Optional[User]:
    return session.exec(select(User).where(User.username == username)).first()

def authenticate_user(session: Session, username: str, password: str) -> Optional[User]:
    user = get_user(session, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    with Session(engine) as session:
        user = get_user(session, username=token_data.username)
        if user is None:
            raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def has_tenant_role(required_role: TenantRole, tenant_id: str) -> Callable:
    def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.app_role == AppWideRole.SUPERUSER:
            return current_user
        for access in current_user.tenant_access:
            if access.tenant_id == tenant_id and access.role == required_role:
                return current_user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions for this tenant"
        )
    return role_checker

def is_superuser(current_user: User = Depends(get_current_active_user)):
    if current_user.app_role != AppWideRole.SUPERUSER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    return current_user

@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)

@app.post("/api/auth/register", response_model=User)
async def register(username: str, password: str, email: Optional[str] = None, full_name: Optional[str] = None):
    with Session(engine) as session:
        existing_user = get_user(session, username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        
        hashed_password = get_password_hash(password)
        new_tenant_name = f"tenant_{username}"
        new_user = User(username=username, email=email, full_name=full_name, hashed_password=hashed_password)
        new_tenant = Tenant(name=new_tenant_name, user_created=new_user)
        new_tenant_access = TenantAccess(tenant_id=new_tenant.id, role=TenantRole.ADMIN)
        new_user.tenant_access = [new_tenant_access]
        
        session.add(new_user)
        session.add(new_tenant)
        session.add(new_tenant_access)
        session.commit()
        session.refresh(new_user)
        return new_user

@app.post("/api/auth/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    with Session(engine) as session:
        user = authenticate_user(session, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/google", response_model=Token)
async def google_login(token: str):
    try:
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), "YOUR_GOOGLE_CLIENT_ID")
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        email = idinfo['email']
        name = idinfo['name']

        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == email)).first()
            if not user:
                new_tenant_name = f"{email.split('@')[0]}'s project"
                new_user = User(
                    username=email,
                    email=email,
                    full_name=name,
                    hashed_password="",  # No password for Google-authenticated users
                    app_role=AppWideRole.STANDARD
                )
                new_tenant = Tenant(name=new_tenant_name, user_created_id=new_user.id)
                new_tenant_access = TenantAccess(tenant_id=new_tenant.id, role=TenantRole.ADMIN)
                new_user.tenant_access = [new_tenant_access]
                session.add(new_tenant)
                session.add(new_tenant_access)
                session.add(new_user)
                session.commit()
                session.refresh(new_user)
                user = new_user

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid token")

#original old
# @app.get("/api/auth/user", response_model=User)
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
#     with Session(engine) as session:
#         users = session.get(User, current_user.id)
#         if not users:
#             raise HTTPException(status_code=404, detail="User not found")
#         return users

#gets basic user data along with Tenants that the user has access to(including roles)
#TODO is there better way in sqlmodel than manually populating?
@app.get("/api/auth/user", response_model=UserWithTenant)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    with Session(engine) as session:
        # Query the tenant access for the user
        tenant_access_records = session.exec(select(TenantAccess).where(TenantAccess.user_id == current_user.id)).all()

        #TODO it already returns tenants !!! maybe it could be automatically transformed to TenantWithRole
        print(tenant_access_records)
        # Map tenant access records to TenantWithRole
        tenant_access_list = [
            TenantWithRole(
                id=ta.tenant.id,
                name=ta.tenant.name, #it is lazy loaded when necessary
                role=ta.role,
                date_created=ta.tenant.date_created
            )
            for ta in tenant_access_records
        ]

        # Construct UserWithTenant
        user_with_tenant = UserWithTenant(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            full_name=current_user.full_name,
            app_role=current_user.app_role,
            tenant_access=tenant_access_list
        )

        return user_with_tenant


@app.get("/api/tenant/{tenant_id}/data")
async def get_tenant_data(tenant_id: str = Path(..., description="The ID of the tenant"), 
                          current_user: User = Depends(lambda: has_tenant_role(TenantRole.LEVEL1, tenant_id))
                          ):
    user_role = next((access.role for access in current_user.tenant_access if access.tenant_id == tenant_id), None)
    return {
        "message": f"Data for tenant {tenant_id}",
        "user_role": user_role,
        "data": [1, 2, 3, 4, 5]  # Replace with actual data retrieval logic
    }

@app.get("/api/admin/users")
async def get_all_users(current_user: User = Depends(is_superuser)):
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return users

@app.post("/api/tenant/{tenant_id}/invite")
async def invite_user_to_tenant(
    tenant_id: str,
    username: str,
    role: TenantRole,
    current_user: User = Depends(lambda: has_tenant_role(TenantRole.ADMIN, tenant_id))
):
    with Session(engine) as session:
        user = session.exec(select(User).where(User.username == username)).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        new_tenant_access = TenantAccess(tenant_id=tenant_id, role=role)
        user.tenant_access.append(new_tenant_access)
        session.add(user)
        session.commit()
        return {"message": f"User {username} invited to tenant {tenant_id} with role {role}"}

@app.get("/api/config")
async def get_app_config(current_user: User = Depends(is_superuser)):
    return {"app_config": "This is the app-wide configuration accessible only to superusers"}

if __name__ == "__main__":
    uvicorn.run("__main__:app", host="0.0.0.0", port=8000, reload=True)


#continue with sqlmodel documentaiton here https://sqlmodel.tiangolo.com/tutorial/fastapi/relationships/#update-the-path-operations
#test in the single script