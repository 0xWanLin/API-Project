from sqlalchemy.orm import Session
from projectAPI import models, schemas


def get_domain_ip(db: Session, id: str): # read domain and ip details by id
    return db.query(models.DomainIP).filter(models.DomainIP.id == id).first()

def get_communicating(db: Session, id: str, skip: int = 0, limit: int = 100): # read domain's communicating files by domain id or ip id
    return db.query(models.CommunicatingFiles).filter(models.CommunicatingFiles.id == id).all()

def get_referring(db: Session, id: str, skip: int = 0, limit: int = 100):  # read domain's referring files by domain id or ip id
    return db.query(models.ReferringFiles).filter(models.ReferringFiles.id == id).all()

def get_all_domainipinfo(db: Session, id: str):  # read all infos by domain id or ip id
    return db.query(models.DomainIP).filter(models.DomainIP.id == id).first()

def get_file(db: Session, file_id: str): # read file details by file_id
    return db.query(models.File).filter(models.File.file_id == file_id).first()

def get_execution(db: Session, file_id: str, skip: int = 0, limit: int = 100): # read execution parents by file_id
    return db.query(models.ExecutionParents).filter(models.ExecutionParents.file_id == file_id).all()

def get_all_file_info(db: Session, file_id: str): # read all infos by file id
    return db.query(models.File).filter(models.File.file_id == file_id).first()