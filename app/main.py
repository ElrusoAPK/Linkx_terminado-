import os, csv, io
from pathlib import Path
from datetime import datetime, date, time, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Optional
import jwt
from fastapi import FastAPI, Depends, HTTPException, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr, Field
from pwdlib import PasswordHash
from sqlalchemy import create_engine, String, Integer, Date as SQLDate, Time as SQLTime, DateTime, ForeignKey, select, inspect as sa_inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session

ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./linkx_asistencia.db")
if DB_URL.startswith("postgres://"): DB_URL = DB_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DB_URL.startswith("postgresql://") and "+psycopg" not in DB_URL: DB_URL = DB_URL.replace("postgresql://", "postgresql+psycopg://", 1)
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    name: Mapped[str]=mapped_column(String(120),nullable=False)
    email: Mapped[str]=mapped_column(String(255),unique=True,index=True,nullable=False)
    password_hash: Mapped[str]=mapped_column(String(255),nullable=False)
    role: Mapped[str]=mapped_column(String(20),default="employee",nullable=False)
    active: Mapped[int]=mapped_column(Integer,default=1,nullable=False)
    must_change_password: Mapped[int]=mapped_column(Integer,default=0,nullable=False)
    created_at: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
    attendance: Mapped[list["Attendance"]]=relationship(back_populates="user")
class Attendance(Base):
    __tablename__="attendance"
    id: Mapped[int]=mapped_column(Integer,primary_key=True)
    user_id: Mapped[int]=mapped_column(ForeignKey("users.id"),index=True,nullable=False)
    movement: Mapped[str]=mapped_column(String(10),nullable=False)
    work_date: Mapped[date]=mapped_column(SQLDate,index=True,nullable=False)
    work_time: Mapped[time]=mapped_column(SQLTime,nullable=False)
    user: Mapped[User]=relationship(back_populates="attendance")
Base.metadata.create_all(bind=engine)
# Agrega la columna a bases existentes sin borrar datos.
if "must_change_password" not in {c["name"] for c in sa_inspect(engine).get_columns("users")}:
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"))
app=FastAPI(title="LINK X Sistemas - API de Asistencia",version="1.0.0")
if STATIC_DIR.exists(): app.mount("/static",StaticFiles(directory=str(STATIC_DIR)),name="static")
password_hash=PasswordHash.recommended()
JWT_SECRET=os.getenv("JWT_SECRET","local-dev-secret-change-me")
security=HTTPBearer(auto_error=False)
class LoginIn(BaseModel):
    email: EmailStr
    password: str
class UserCreate(BaseModel):
    name: str=Field(min_length=2,max_length=120)
    email: EmailStr
    password: str=Field(min_length=6,max_length=128)
    role: str="employee"
def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()
def user_dict(u): return {"id":u.id,"name":u.name,"email":u.email,"role":u.role,"active":bool(u.active),"must_change_password":bool(u.must_change_password)}
def att_dict(a): return {"id":a.id,"user_id":a.user_id,"name":a.user.name,"email":a.user.email,"movement":a.movement,"date":a.work_date.isoformat(),"time":a.work_time.strftime("%H:%M:%S")}
def seed_admin():
    email=os.getenv("ADMIN_EMAIL","admin@linkx.local").strip().lower()
    password=os.getenv("ADMIN_PASSWORD")
    if not password: return
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.email==email)):
            db.add(User(name=os.getenv("ADMIN_NAME","Administrador LINK X"),email=email,password_hash=password_hash.hash(password),role="admin")); db.commit()
seed_admin()
def current_user(creds: Optional[HTTPAuthorizationCredentials]=Depends(security),db: Session=Depends(get_db)):
    if not creds: raise HTTPException(401,"Inicia sesión para continuar.")
    try: uid=int(jwt.decode(creds.credentials,JWT_SECRET,algorithms=["HS256"])["sub"])
    except Exception: raise HTTPException(401,"Sesión inválida o expirada.")
    u=db.get(User,uid)
    if not u or not u.active: raise HTTPException(401,"Cuenta no disponible.")
    return u
def verified_user(u: User=Depends(current_user)):
    if u.must_change_password: raise HTTPException(403,"Debes cambiar tu contraseña antes de continuar.")
    return u
def admin_only(u: User=Depends(verified_user)):
    if u.role!="admin": raise HTTPException(403,"Acceso exclusivo para administrador.")
    return u
def make_token(u):
    now=datetime.now(timezone.utc)
    return jwt.encode({"sub":str(u.id),"role":u.role,"iat":now,"exp":now+timedelta(minutes=int(os.getenv("ACCESS_TOKEN_MINUTES","480")))},JWT_SECRET,algorithm="HS256")
@app.get("/api/health")
def health(): return {"status":"ok","service":"LINK X Asistencia"}
@app.post("/api/auth/login")
def login(data: LoginIn,db: Session=Depends(get_db)):
    u=db.scalar(select(User).where(User.email==data.email.lower().strip()))
    if not u or not u.active or not password_hash.verify(data.password,u.password_hash): raise HTTPException(401,"Correo o contraseña incorrectos.")
    return {"access_token":make_token(u),"token_type":"bearer","user":user_dict(u)}
@app.get("/api/auth/me")
def me(u: User=Depends(current_user)): return user_dict(u)
@app.post("/api/auth/change-password")
def change_password(payload: dict,u: User=Depends(verified_user),db: Session=Depends(get_db)):
    if not password_hash.verify(str(payload.get("current_password","")),u.password_hash): raise HTTPException(400,"La contraseña actual no coincide.")
    new=str(payload.get("new_password",""))
    if len(new)<6: raise HTTPException(400,"La nueva contraseña debe tener al menos 6 caracteres.")
    u.password_hash=password_hash.hash(new); u.must_change_password=0; db.commit(); return {"message":"Contraseña actualizada.","user":user_dict(u)}
@app.get("/api/users")
def list_users(_: User=Depends(admin_only),db: Session=Depends(get_db)):
    return [user_dict(u) for u in db.scalars(select(User).order_by(User.name)).all()]
@app.post("/api/users",status_code=201)
def create_user(data: UserCreate,_: User=Depends(admin_only),db: Session=Depends(get_db)):
    email=data.email.lower().strip()
    if data.role not in ("employee","admin"): raise HTTPException(400,"Perfil inválido.")
    if db.scalar(select(User).where(User.email==email)): raise HTTPException(409,"Ese correo ya está registrado.")
    u=User(name=data.name.strip(),email=email,password_hash=password_hash.hash(data.password),role=data.role,must_change_password=1)
    db.add(u); db.commit(); db.refresh(u); return user_dict(u)
@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(user_id: int,payload: dict,_: User=Depends(admin_only),db: Session=Depends(get_db)):
    u=db.get(User,user_id)
    if not u: raise HTTPException(404,"Usuario no encontrado.")
    new_password=str(payload.get("password", ""))
    if len(new_password)<6 or len(new_password)>128: raise HTTPException(400,"La contraseña temporal debe tener entre 6 y 128 caracteres.")
    u.password_hash=password_hash.hash(new_password)
    u.must_change_password=1
    db.commit()
    return {"message":"Contraseña restablecida. El usuario deberá cambiarla al iniciar sesión.","user":user_dict(u)}
@app.patch("/api/users/{user_id}/active")
def toggle_user(user_id: int,payload: dict,admin: User=Depends(admin_only),db: Session=Depends(get_db)):
    u=db.get(User,user_id)
    if not u: raise HTTPException(404,"Usuario no encontrado.")
    active=bool(payload.get("active"))
    if u.id==admin.id and not active: raise HTTPException(400,"No puedes desactivar tu propia cuenta.")
    u.active=int(active); db.commit(); return user_dict(u)
@app.post("/api/attendance/{movement}",status_code=201)
def mark_attendance(movement: str,u: User=Depends(verified_user),db: Session=Depends(get_db)):
    if movement not in ("entrada","salida"): raise HTTPException(400,"Movimiento no válido.")
    now=datetime.now(ZoneInfo(os.getenv("APP_TIMEZONE","America/Mexico_City"))); today=now.date()
    records=db.scalars(select(Attendance).where(Attendance.user_id==u.id,Attendance.work_date==today).order_by(Attendance.work_time)).all()
    if movement=="entrada" and any(a.movement=="Entrada" for a in records): raise HTTPException(409,"Ya registraste tu entrada de hoy.")
    if movement=="salida" and not any(a.movement=="Entrada" for a in records): raise HTTPException(409,"Primero debes registrar tu entrada.")
    if movement=="salida" and any(a.movement=="Salida" for a in records): raise HTTPException(409,"Ya registraste tu salida de hoy.")
    a=Attendance(user_id=u.id,movement="Entrada" if movement=="entrada" else "Salida",work_date=today,work_time=now.time().replace(tzinfo=None,microsecond=0))
    db.add(a); db.commit(); db.refresh(a); return att_dict(a)
@app.get("/api/attendance/mine")
def my_attendance(start: Optional[date]=None,end: Optional[date]=None,u: User=Depends(verified_user),db: Session=Depends(get_db)):
    q=select(Attendance).where(Attendance.user_id==u.id)
    if start: q=q.where(Attendance.work_date>=start)
    if end: q=q.where(Attendance.work_date<=end)
    return [att_dict(a) for a in db.scalars(q.order_by(Attendance.work_date.desc(),Attendance.work_time.desc())).all()]
@app.get("/api/attendance")
def all_attendance(start: Optional[date]=None,end: Optional[date]=None,user_id: Optional[int]=None,_: User=Depends(admin_only),db: Session=Depends(get_db)):
    q=select(Attendance)
    if start: q=q.where(Attendance.work_date>=start)
    if end: q=q.where(Attendance.work_date<=end)
    if user_id: q=q.where(Attendance.user_id==user_id)
    return [att_dict(a) for a in db.scalars(q.order_by(Attendance.work_date.desc(),Attendance.work_time.desc())).all()]
@app.get("/api/attendance/today-summary")
def today_summary(_: User=Depends(admin_only),db: Session=Depends(get_db)):
    today=datetime.now(ZoneInfo(os.getenv("APP_TIMEZONE","America/Mexico_City"))).date()
    people=db.scalars(select(User).where(User.role!="admin",User.active==1).order_by(User.name)).all(); result=[]
    for u in people:
        rows=db.scalars(select(Attendance).where(Attendance.user_id==u.id,Attendance.work_date==today).order_by(Attendance.work_time)).all()
        en=next((a for a in rows if a.movement=="Entrada"),None); sa=next((a for a in reversed(rows) if a.movement=="Salida"),None)
        result.append({"user":user_dict(u),"entry":en.work_time.strftime("%H:%M:%S") if en else None,"exit":sa.work_time.strftime("%H:%M:%S") if sa else None,"status":"Jornada cerrada" if sa else ("En jornada" if en else "Sin registro")})
    return result
@app.get("/api/reports/attendance.csv")
def export_csv(start: Optional[date]=None,end: Optional[date]=None,user_id: Optional[int]=None,_: User=Depends(admin_only),db: Session=Depends(get_db)):
    q=select(Attendance)
    if start:q=q.where(Attendance.work_date>=start)
    if end:q=q.where(Attendance.work_date<=end)
    if user_id:q=q.where(Attendance.user_id==user_id)
    rows=db.scalars(q.order_by(Attendance.work_date.desc(),Attendance.work_time.desc())).all()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["Nombre","Correo","Movimiento","Fecha","Hora"])
    for a in rows:w.writerow([a.user.name,a.user.email,a.movement,a.work_date.isoformat(),a.work_time.strftime("%H:%M:%S")])
    return Response(content="\ufeff"+out.getvalue(),media_type="text/csv; charset=utf-8",headers={"Content-Disposition":'attachment; filename="reporte_asistencia.csv"'})
@app.get("/")
def home():
    file=STATIC_DIR/"index.html"
    if not file.exists(): return {"message":"Frontend pendiente de instalar","docs":"/docs"}
    return FileResponse(str(file))
