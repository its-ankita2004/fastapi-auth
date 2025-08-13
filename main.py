from fastapi import FastAPI, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from database import SessionLocal, engine
import models, schemas, auth
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import jwt, JWTError



models.Base.metadata.create_all(bind=engine)
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://its-ankita2004.github.io"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    print("Registering user:", db.query(models.User))
    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = auth.get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    token = auth.create_access_token({"sub": user.email})

    return {"message": "User registered successfully", "access_token": token, "token_type": "bearer"}

@app.post("/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user or not auth.verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth.create_access_token({"sub": user.email})
    # Create a response with token and message
    response = JSONResponse(content={
        "message": "User logged in successfully",
        "access_token": token,
        "token_type": "bearer"
    })
        # Set token in cookie
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,  # Set to True in production with HTTPS
        samesite="None"
    )
    return response

@app.get("/protected")
def protected(request: Request):
    token = request.cookies.get("access_token")
    if not token:
       raise HTTPException(status_code=401, detail="Token missing")
    try:
        payload = auth.decode_token(token)
        user_email = payload.get("sub")
        return {"message": f"Hello {user_email}, you accessed a protected route!"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
