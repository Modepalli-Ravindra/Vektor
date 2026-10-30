"""
Database module for SQLite scan history and user authentication
"""
from datetime import datetime
import os
import hashlib
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = f"sqlite:///{os.path.join(DB_DIR, 'scans.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, index=True)
    file_type = Column(String)
    file_size_bytes = Column(Integer)
    sha256 = Column(String, index=True)
    prediction = Column(String)  # Malware or Benign
    confidence = Column(Float)
    raw_score = Column(Float)
    threshold = Column(Float)
    platform = Column(String, default="Windows PE")
    timestamp = Column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


def hash_password(password: str) -> str:
    salt = "sentinel_auth_salt_2026"
    return hashlib.sha256((password + salt).encode()).hexdigest()


def init_db():
    Base.metadata.create_all(bind=engine)
    # Seed default verified user if not exists
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == "admin@security.local").first()
        if not admin:
            db.add(User(
                email="admin@security.local",
                password_hash=hash_password("Admin@1234"),
                created_at=datetime.utcnow()
            ))
            db.commit()
    finally:
        db.close()


def create_user(email: str, password: str):
    email = email.lower().strip()
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return None, "An account with this email already exists."
        user = User(
            email=email,
            password_hash=hash_password(password),
            created_at=datetime.utcnow()
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"id": user.id, "email": user.email}, None
    except Exception as e:
        db.rollback()
        return None, str(e)
    finally:
        db.close()


def authenticate_user(email: str, password: str):
    email = email.lower().strip()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None, "No account found with this email address."
        if user.password_hash != hash_password(password):
            return None, "Incorrect password. Please verify and try again."
        return {"id": user.id, "email": user.email}, None
    finally:
        db.close()


def reset_password(email: str, new_password: str):
    email = email.lower().strip()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False, "No account found with this email address."
        user.password_hash = hash_password(new_password)
        db.commit()
        return True, "Password has been successfully updated."
    except Exception as e:
        db.rollback()
        return False, str(e)
    finally:
        db.close()


def insert_scan(
    filename: str,
    file_type: str,
    file_size_bytes: int,
    sha256: str,
    prediction: str,
    confidence: float,
    raw_score: float,
    threshold: float,
    platform: str = "Windows PE"
) -> ScanRecord:
    db = SessionLocal()
    try:
        record = ScanRecord(
            filename=filename,
            file_type=file_type,
            file_size_bytes=file_size_bytes,
            sha256=sha256,
            prediction=prediction,
            confidence=round(confidence, 2),
            raw_score=round(raw_score, 4),
            threshold=round(threshold, 2),
            platform=platform,
            timestamp=datetime.utcnow()
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    finally:
        db.close()


def get_history(limit: int = 50):
    db = SessionLocal()
    try:
        records = (
            db.query(ScanRecord)
            .order_by(ScanRecord.id.desc())
            .limit(limit)
            .all()
        )
        return [
            {
                "id": r.id,
                "filename": r.filename,
                "file_type": r.file_type,
                "file_size_bytes": r.file_size_bytes,
                "sha256": r.sha256,
                "prediction": r.prediction,
                "confidence": r.confidence,
                "raw_score": r.raw_score,
                "threshold": r.threshold,
                "platform": r.platform,
                "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else ""
            }
            for r in records
        ]
    finally:
        db.close()


def get_stats():
    db = SessionLocal()
    try:
        total = db.query(ScanRecord).count()
        malware_count = db.query(ScanRecord).filter(ScanRecord.prediction == "Malware").count()
        benign_count = db.query(ScanRecord).filter(ScanRecord.prediction == "Benign").count()
        
        avg_conf = 0.0
        if total > 0:
            records = db.query(ScanRecord.confidence).all()
            avg_conf = round(sum(r[0] for r in records) / total, 2)
            
        threat_rate = round((malware_count / total * 100), 1) if total > 0 else 0.0

        return {
            "total_scans": total,
            "malware_detected": malware_count,
            "benign_detected": benign_count,
            "threat_rate_percent": threat_rate,
            "average_confidence": avg_conf
        }
    finally:
        db.close()


def clear_history():
    db = SessionLocal()
    try:
        db.query(ScanRecord).delete()
        db.commit()
        return True
    finally:
        db.close()
