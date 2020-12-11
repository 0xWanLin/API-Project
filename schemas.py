from typing import List, Optional
from datetime import datetime

from pydantic import BaseModel

# creating all these schemas is to have common attributes while reading data
class CommunicatingFiles(BaseModel): 
    id: str
    communicating_id: str
    date_scanned: datetime
    detection_score: str
    severity: str
    type: str
    name: str
    
    class Config:
        orm_mode = True # read the data even if it's not a dict so instead of getting only id value from a dict
                        # it will also get from an attribute (e.g. id = data.id)

class ReferringFiles(BaseModel):
    id: str
    referring_id: str
    date_scanned: datetime
    detection_score: str
    severity: str
    type: str
    name: str
    
    class Config:
        orm_mode = True

class DomainIPBase(BaseModel):
    id: str
    type: str
    score: str
    severity: str
    date: datetime

class DomainIP(DomainIPBase): # to fetch only the data for values shown in this class
    communicating_files: List[CommunicatingFiles] = [] # get the attributes from Communicating Files into a List
    referring_files: List[ReferringFiles] = [] # get the attributes from Referring Files into a List
    
    class Config:
        orm_mode = True

class DomainIPDetails(DomainIPBase):
    id: str
    type: str
    score: str
    severity: str
    date: datetime

    class Config:
        orm_mode = True

class ExecutionParents(BaseModel):
    execution_id: str
    file_id: str
    date_scanned: datetime
    detection_score: str
    severity: str
    type: str
    name: str

    class Config:
        orm_mode = True

class FileBase(BaseModel): 
    file_id: str
    type: str
    score: str
    severity: str
    tags: str
    date: datetime

class File(FileBase): # to fetch only the data for values shown in this class
    exec_parents: List[ExecutionParents] = [] # get the attributes from Execution Parents into a List

    class Config:
        orm_mode = True

class FileDetails(FileBase):
    file_id: str
    type: str
    score: str
    severity: str
    tags: str
    date: datetime

    class Config:
        orm_mode = True



   

