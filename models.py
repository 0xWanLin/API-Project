from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime, VARCHAR, Text
from sqlalchemy.orm import relationship

from .database import Base

class DomainIP(Base):
    __tablename__ = "domain_ip_scans" # this attribute tells SQLAlchemy the name of the table to use in our db

    id = Column(VARCHAR, primary_key=True)
    type = Column(VARCHAR)
    score = Column(VARCHAR)             # all these attributes = columns in our db tables
    severity = Column(VARCHAR)
    date = Column (DateTime)

    communicating_files = relationship("CommunicatingFiles") # relationships: contain values from other tables related to this a.k.a foreign key
    referring_files = relationship("ReferringFiles") # relationships: contain values from other tables related to this

class CommunicatingFiles(Base):
    __tablename__ = "communicating_files"
    
    communicating_id = Column(VARCHAR, primary_key=True)
    id = Column(VARCHAR, ForeignKey("domain_ip_scans.id"))
    date_scanned = Column(DateTime)
    detection_score = Column(VARCHAR)       # all these attributes = columns in our db tables
    severity = Column(VARCHAR)
    type = Column(VARCHAR)
    name = Column(Text)
    
class ReferringFiles(Base):
    __tablename__ = "referring_files"

    referring_id = Column(VARCHAR, primary_key=True)
    id = Column(VARCHAR, ForeignKey("domain_ip_scans.id"))
    date_scanned = Column(DateTime)
    detection_score = Column(VARCHAR)       # all these attributes = columns in our db tables
    severity = Column(VARCHAR)
    type = Column(VARCHAR)
    name = Column(Text)

class File(Base):
    __tablename__ = "file_scans"

    file_id = Column(VARCHAR, primary_key=True)
    type = Column(VARCHAR)
    score = Column(VARCHAR)
    severity = Column(VARCHAR)          # all these attributes = columns in our db tables
    tags = Column(VARCHAR)
    date = Column (VARCHAR)

    exec_parents = relationship("ExecutionParents") # relationships: contain values from other tables related to this

class ExecutionParents(Base):
    __tablename__ = "execution_parents"

    execution_id = Column(VARCHAR, primary_key=True)
    file_id = Column(VARCHAR, ForeignKey("file_scans.file_id"))
    date_scanned = Column(DateTime)
    detection_score = Column(VARCHAR)       # all these attributes = columns in our db tables
    severity = Column(VARCHAR)
    type = Column(VARCHAR)
    name = Column(Text)
    