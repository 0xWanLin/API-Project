from typing import Optional, List
from datetime import datetime, time, timedelta
import psycopg2
import re
import json, urllib.request, requests
from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from projectAPI import crud, models, schemas
from .database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine) # create the db tables

projectapi = FastAPI(docs_url="/scan")

# dependency, this will create a new sessionlocal (used in a single request) and close it once the request is finished
def get_db():
    db = SessionLocal()
    try: # try in a dependency with yield, will receive any exception that was thrown
        yield db
    finally: # this is to make sure exit steps are executed, no matter if there was an exception or not
        db.close() 

# get all information for domains and ip addresses
@projectapi.get("/scan/domain_ip/{id}/all_information", response_model=schemas.DomainIP, tags=["all_information_for_domain_or_ip"])
def get_all_information_for_domain_or_ip(id: str, db: Session = Depends(get_db)): # declare with the type Session (imported directly from SQLAlchemy) and dependency 
    db_all_information_for_domain_or_ip = crud.get_all_domainipinfo(db, id=id) # get crud here
    # return db_domain_ip
    if db_all_information_for_domain_or_ip is None:    # logic function
        print("Please wait...")
        regex = str("([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}") # for domain, it is a regex to differentiate domains and IP addresses
        if re.match(regex, id) is not None: # if input (x) and the regex match, it will run the domain section
            # domain_scans
            url = 'https://www.virustotal.com/api/v3/domains/' + id
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'}) # you can change your api-key in here
            response_dict = json.loads(response.text)

            # communicating_files
            url = 'https://www.virustotal.com/api/v3/domains/' + id + '/communicating_files'
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
            response_communicating_dict = json.loads(response.text)

            # referring_files
            url = 'https://www.virustotal.com/api/v3/domains/' + id + '/referrer_files'
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
            response_referring_dict = json.loads(response.text)

            try:
                conn = psycopg2.connect(database='VirusTotal', user='postgres', password='postgres', host='127.0.0.1', port='5432')

            except:
                print("I am unable to connect to the database.")

            #cursor
            cur = conn.cursor()

            # domain_scans
            # getting data from the dictionary list saved with the json data
            domain_id = response_dict['data']['id']
            domain_date = response_dict['data']['attributes']['whois_date']
            domain_type = response_dict['data']['type']
            domain_harmless_score = response_dict['data']['attributes']['last_analysis_stats']['harmless']
            domain_malicious_score = response_dict['data']['attributes']['last_analysis_stats']['malicious']
            domain_suspicious_score = response_dict['data']['attributes']['last_analysis_stats']['suspicious']
            domain_timeout_score = response_dict['data']['attributes']['last_analysis_stats']['timeout']
            domain_undetected_score = response_dict['data']['attributes']['last_analysis_stats']['undetected']
            domainDate = datetime.fromtimestamp(domain_date).strftime('%Y-%m-%d %I:%M:%S')
            domain_score = str(domain_malicious_score + domain_suspicious_score) + "/" + str(domain_harmless_score + domain_malicious_score + domain_suspicious_score + domain_timeout_score + domain_undetected_score)

            if domain_malicious_score + domain_suspicious_score >= 25:
                domain_severity = "High"

            elif domain_malicious_score + domain_suspicious_score >= 15:
                domain_severity = "Medium"

            else:
                domain_severity = "Low"

            domain_records = (domain_id, domain_type, domain_score, domain_severity, domainDate)

            # prepared statement for domain_ip_scans
            cur.execute(
                "PREPARE domain_request AS "
                "INSERT INTO domain_ip_scans VALUES ($1, $2, $3, $4, $5)")
            cur.execute("EXECUTE domain_request (%s, %s, %s, %s, %s)", domain_records) # %s for string
            cur.execute("DEALLOCATE domain_request")
            conn.commit()

            # communicating_files
            # getting data from the dictionary list saved with the json data
            x = 0
            while x != len(response_communicating_dict['data']):
                communicating_id = response_communicating_dict['data'][x]['id']
                communicating_date = response_communicating_dict['data'][x]['attributes']['last_submission_date']
                communicating_harmless_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
                communicating_malicious_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
                communicating_suspicious_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
                communicating_timeout_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
                communicating_undetected_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
                communicating_type = response_communicating_dict['data'][x]['attributes']['type_description']
                communicating_name = response_communicating_dict['data'][x]['attributes']['names']
                date_time = datetime.fromtimestamp(communicating_date).strftime('%Y-%m-%d %I:%M:%S')
                communicating_score = str(communicating_malicious_score + communicating_suspicious_score) + "/" + str(communicating_harmless_score + communicating_malicious_score + communicating_suspicious_score + communicating_timeout_score + communicating_undetected_score)
                communicating_name_obj = str(communicating_name)[1:-1]

                if communicating_malicious_score + communicating_suspicious_score >= 25:
                    communicating_severity = "High"

                elif communicating_malicious_score + communicating_suspicious_score >= 15:
                    communicating_severity = "Medium"  

                else:
                    communicating_severity = "Low"

                # prepared statement for communicating_files
                communicating_records = (communicating_id, domain_id, date_time, communicating_score, communicating_severity, communicating_type, communicating_name_obj)
                cur.execute(
                    "PREPARE communicating_request AS "
                    "INSERT INTO communicating_files VALUES ($1, $2, $3, $4, $5, $6, $7)")
                cur.execute("EXECUTE communicating_request (%s, %s, %s, %s, %s, %s, %s)", communicating_records)
                cur.execute("DEALLOCATE communicating_request")
                conn.commit()

                x+=1

            # referring_files
            # getting data from the dictionary list saved with the json data
            x = 0
            while x != len(response_referring_dict['data']):
                referring_id = response_communicating_dict['data'][x]['id']
                referring_date = response_referring_dict['data'][x]['attributes']['last_submission_date']
                referring_harmless_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
                referring_malicious_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
                referring_suspicious_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
                referring_timeout_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
                referring_undetected_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
                referring_type = response_referring_dict['data'][x]['attributes']['type_description']
                referring_name = response_referring_dict['data'][x]['attributes']['names']
                date_time = datetime.fromtimestamp(referring_date).strftime('%Y-%m-%d %I:%M:%S')
                referring_score = str(referring_malicious_score + referring_suspicious_score) + "/" + str(referring_harmless_score + referring_malicious_score + referring_suspicious_score + referring_timeout_score + referring_undetected_score)
                referring_name_obj = str(referring_name)[1:-1]

                if referring_malicious_score + referring_suspicious_score >= 25:
                    referring_severity = "High"

                elif referring_malicious_score + referring_suspicious_score >= 15: 
                    referring_severity = "Medium"
                    
                else:
                    referring_severity = "Low"

                # prepared statement for referring_files
                referring_records = (referring_id, domain_id, date_time, referring_score, referring_severity, referring_type, referring_name_obj)
                cur.execute(
                    "PREPARE referring_request AS "
                    "INSERT INTO referring_files VALUES ($1, $2, $3, $4, $5, $6, $7)"
                )
                cur.execute("EXECUTE referring_request (%s, %s, %s, %s, %s, %s, %s)", (referring_records))
                cur.execute("DEALLOCATE referring_request")
                conn.commit()

                x+=1

        else: # if the regex and the input does not match (e.g. IP address), it will run the IP section
            # ip_scans
            url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'}) # you can change your api-key in here
            response_ip_dict = json.loads(response.text)

            # communicating_files
            url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id + '/communicating_files'
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
            response_ipcomms_dict = json.loads(response.text)

            # referring_files
            url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id + '/referrer_files'
            response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
            response_ipreferring_dict = json.loads(response.text)

            try:
                conn = psycopg2.connect(database='VirusTotal', user='postgres', password='postgres', host='127.0.0.1', port='5432')

            except:
                print("I am unable to connect to the database.")

            #cursor
            cur = conn.cursor()

            # ip_scans
            # getting data from the dictionary list saved with the json data
            ip_id = response_ip_dict['data']['id']
            ip_date = response_ip_dict['data']['attributes']['whois_date']
            ip_type = response_ip_dict['data']['type']
            ip_harmless_score = response_ip_dict['data']['attributes']['last_analysis_stats']['harmless']
            ip_malicious_score = response_ip_dict['data']['attributes']['last_analysis_stats']['malicious']
            ip_suspicious_score = response_ip_dict['data']['attributes']['last_analysis_stats']['suspicious']
            ip_timeout_score = response_ip_dict['data']['attributes']['last_analysis_stats']['timeout']
            ip_undetected_score = response_ip_dict['data']['attributes']['last_analysis_stats']['undetected']
            ipDate = datetime.fromtimestamp(ip_date).strftime('%Y-%m-%d %I:%M:%S')
            ip_score = str(ip_malicious_score + ip_suspicious_score) + "/" + str(ip_harmless_score + ip_malicious_score + ip_suspicious_score + ip_timeout_score + ip_undetected_score)

            if ip_malicious_score + ip_suspicious_score >= 25:
                ip_severity = "High"

            elif ip_malicious_score + ip_suspicious_score >= 15:
                ip_severity = "Medium"

            else:
                ip_severity = "Low"

            ip_records = (ip_id, ip_type, ip_score, ip_severity, ipDate)
            
            # prepared statements for domain_ip_scans
            cur.execute(
                "PREPARE ip_request AS "
                "INSERT INTO domain_ip_scans VALUES ($1, $2, $3, $4, $5)"
            )
            cur.execute("EXECUTE ip_request (%s, %s, %s, %s, %s)", (ip_records)) #%s for string
            cur.execute("DEALLOCATE ip_request")
            conn.commit()

            # ip_communicating_files
            # getting data from the dictionary list saved with the json data
            x = 0
            while x != len(response_ipcomms_dict['data']):
                ipcomms_id = response_ipcomms_dict['data'][x]['id']
                ipcomms_date = response_ipcomms_dict['data'][x]['attributes']['last_submission_date']
                ipcomms_harmless_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
                ipcomms_malicious_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
                ipcomms_suspicious_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
                ipcomms_timeout_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
                ipcomms_undetected_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
                ipcomms_type = response_ipcomms_dict['data'][x]['attributes']['type_description']
                ipcomms_name = response_ipcomms_dict['data'][x]['attributes']['names']
                date_time = datetime.fromtimestamp(ipcomms_date).strftime('%Y-%m-%d %I:%M:%S')
                ipcomms_score = str(ipcomms_malicious_score + ipcomms_suspicious_score) + "/" + str(ipcomms_harmless_score + ipcomms_malicious_score + ipcomms_suspicious_score + ipcomms_timeout_score + ipcomms_undetected_score)
                ipcomms_name_obj = str(ipcomms_name)[1:-1]

                if ipcomms_malicious_score + ipcomms_suspicious_score >= 25:
                    ipcomms_severity = "High"

                elif ipcomms_malicious_score + ipcomms_suspicious_score >= 15:
                    ipcomms_severity = "Medium"  

                else:
                    ipcomms_severity = "Low"

                # prepared statement for communicating_files
                ipcomms_records = (ipcomms_id, ip_id, date_time, ipcomms_score, ipcomms_severity, ipcomms_type, ipcomms_name_obj)
                cur.execute(
                    "PREPARE ipcommunicating_request AS "
                    "INSERT INTO communicating_files VALUES ($1, $2, $3, $4, $5, $6, $7)")
                cur.execute("EXECUTE ipcommunicating_request (%s, %s, %s, %s, %s, %s, %s)", ipcomms_records)
                cur.execute("DEALLOCATE ipcommunicating_request")
                conn.commit()

                x+=1

            # ip_referring_files
            # getting data from the dictionary list saved with the json data
            x = 0
            while x != len(response_ipreferring_dict['data']):
                ipreferring_id = response_ipreferring_dict['data'][x]['id']
                ipreferring_date = response_ipreferring_dict['data'][x]['attributes']['last_submission_date']
                ipreferring_harmless_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
                ipreferring_malicious_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
                ipreferring_suspicious_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
                ipreferring_timeout_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
                ipreferring_undetected_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
                ipreferring_type = response_ipreferring_dict['data'][x]['attributes']['type_description']
                ipreferring_name = response_ipreferring_dict['data'][x]['attributes']['names']
                date_time = datetime.fromtimestamp(ipreferring_date).strftime('%Y-%m-%d %I:%M:%S')
                ipreferring_score = str(ipreferring_malicious_score + ipreferring_suspicious_score) + "/" + str(ipreferring_harmless_score + ipreferring_malicious_score + ipreferring_suspicious_score + ipreferring_timeout_score + ipreferring_undetected_score)
                ipreferring_name_obj = str(ipreferring_name)[1:-1]

                if ipreferring_malicious_score + ipreferring_suspicious_score >= 25:
                    ipreferring_severity = "High"

                elif ipreferring_malicious_score + ipreferring_suspicious_score >= 15: 
                    ipreferring_severity = "Medium"
                    
                else:
                    ipreferring_severity = "Low"

                # prepared statement for referring_files
                ipreferring_records = (ipreferring_id, ip_id, date_time, ipreferring_score, ipreferring_severity, ipreferring_type, ipreferring_name_obj)
                cur.execute(
                    "PREPARE ipreferring_request AS "
                    "INSERT INTO referring_files VALUES ($1, $2, $3, $4, $5, $6, $7)"
                )
                cur.execute("EXECUTE ipreferring_request (%s, %s, %s, %s, %s, %s, %s)", (ipreferring_records))
                cur.execute("DEALLOCATE ipreferring_request")
                conn.commit()

                x+=1

        # close the cursor
        cur.close()

        # close the connection
        conn.close()

        db_all_information_for_domain_or_ip= crud.get_all_domainipinfo(db, id=id)
        return db_all_information_for_domain_or_ip

    else:
        return db_all_information_for_domain_or_ip

# domains and ip
@projectapi.get("/scan/domain_ip/{id}", response_model=schemas.DomainIPDetails, tags=["domains_ip"])
def get_domain_or_ip(id: str, db: Session = Depends(get_db)): # declare with the type Session (imported directly from SQLAlchemy) and dependency 
    db_domain_or_ip = crud.get_domain_ip(db, id=id) # get crud here
    if db_domain_or_ip is None:
        raise HTTPException(status_code=404, detail="Domain/IP not found")
    return db_domain_or_ip

# communicating files for domains and ip addresses
@projectapi.get("/scan/domain_ip/{id}/communicating_files", response_model=List[schemas.CommunicatingFiles], tags=["communicating_files"])
def get_communicating_files(id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    db_communicating = crud.get_communicating(db, id=id) # get crud here
    return db_communicating

# referring files for domains and ip addresses
@projectapi.get("/scan/domain_ip/{id}/referring_files", response_model=List[schemas.ReferringFiles], tags=["referring_files"])
def get_referring_files(id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    db_referring = crud.get_referring(db, id=id) # get crud here
    return db_referring

# files
@projectapi.get("/scan/files/{file_id}/all_information", response_model=schemas.File, tags=["all_information_for_file"])
def get_all_information_for_file(file_id: str, db: Session = Depends(get_db)): 
    db_all_information_for_file = crud.get_all_file_info(db, file_id=file_id) # get crud here
    if db_all_information_for_file is None:    # logic function
        print("Please wait...")
        # file_scans
        url = 'https://www.virustotal.com/api/v3/files/' + file_id
        response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'}) # you can change your api-key in here
        response_file_dict = json.loads(response.text)

        # execution_parents
        url = 'https://www.virustotal.com/api/v3/files/' + file_id + '/execution_parents'
        response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})

        try:
            conn = psycopg2.connect(database='VirusTotal', user='postgres', password='postgres', host='127.0.0.1', port='5432')

        except:
            print("I am unable to connect to the database.")

        #cursor
        cur = conn.cursor()

        # file_scans
        file_id = response_file_dict['data']['id']
        file_date = response_file_dict['data']['attributes']['last_submission_date']
        file_type = response_file_dict['data']['type']
        file_harmless_score = response_file_dict['data']['attributes']['last_analysis_stats']['harmless']
        file_malicious_score = response_file_dict['data']['attributes']['last_analysis_stats']['malicious']
        file_suspicious_score = response_file_dict['data']['attributes']['last_analysis_stats']['suspicious']
        file_timeout_score = response_file_dict['data']['attributes']['last_analysis_stats']['timeout']
        file_undetected_score = response_file_dict['data']['attributes']['last_analysis_stats']['undetected']
        file_tags = response_file_dict['data']['attributes']['tags']
        dateFile = datetime.fromtimestamp(file_date).strftime('%Y-%m-%d %I:%M:%S')
        file_score = str(file_malicious_score + file_suspicious_score) + "/" + str(file_harmless_score + file_malicious_score + file_suspicious_score + file_timeout_score + file_undetected_score)

        if file_malicious_score + file_suspicious_score >= 25:
            file_severity = "High"

        elif file_malicious_score + file_suspicious_score >= 15:
            file_severity = "Medium"
            
        else:
            file_severity = "Low"

        file_tags_obj = str(file_tags)[1:-1]
        file_records = (file_id, file_type, file_score, file_severity, file_tags_obj, dateFile)

        # prepared statements for file_scans
        cur.execute(
            "PREPARE file_request AS "
            "INSERT INTO file_scans VALUES ($1, $2, $3, $4, $5, $6)")
        cur.execute("EXECUTE file_request (%s, %s, %s, %s, %s, %s)", (file_records)) # %s for string
        cur.execute("DEALLOCATE file_request")
        conn.commit()

        # execution_parents
        # getting data from the dictionary list saved with the json data
        if response:
            response_execution_dict = json.loads(response.text)
            x = 0
            while x != len(response_execution_dict['data']):
                for y in response_execution_dict['data'][x]['attributes']['names']:
                    execution_id = response_execution_dict['data'][x]['id']
                    execution_name = response_execution_dict['data'][x]['attributes']['names']
                    execution_date = response_execution_dict['data'][x]['attributes']['last_submission_date']
                    execution_harmless_score = response_execution_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
                    execution_malicious_score = response_execution_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
                    execution_suspicious_score = response_execution_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
                    execution_timeout_score = response_execution_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
                    execution_undetected_score = response_execution_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
                    execution_type = response_execution_dict['data'][x]['attributes']['type_description']
                    date_time = datetime.fromtimestamp(execution_date).strftime('%Y-%m-%d %I:%M:%S')
                    execution_score = str(execution_malicious_score + execution_suspicious_score) + "/" + str(execution_harmless_score + execution_malicious_score + execution_suspicious_score + execution_timeout_score + execution_undetected_score)
                    execution_name_obj = str(execution_name)[1:-1]

                    if execution_malicious_score + execution_suspicious_score >= 25:
                        execution_severity = "High"
                    
                    elif execution_malicious_score + execution_suspicious_score >= 15:
                        execution_severity = "Medium"

                    else:
                        execution_severity = "Low"

                    execution_records = (execution_id, file_id, date_time, execution_score, execution_severity, execution_type, execution_name_obj)
                    
                    # prepared statements for execution_parents
                    cur.execute(
                        "PREPARE execution_request AS "
                        "INSERT INTO execution_parents VALUES ($1, $2, $3, $4, $5, $6, $7)")
                    cur.execute("EXECUTE execution_request (%s, %s, %s, %s, %s, %s, %s)", (execution_records)) # %s for string
                    cur.execute("DEALLOCATE execution_request")
                    conn.commit()

                x+=1

        # close the cursor
        cur.close()

        # close the connection
        conn.close()

        db_all_information_for_file = crud.get_all_file_info(db, file_id=file_id)
        return db_all_information_for_file

    else: 
        return db_all_information_for_file

# files
@projectapi.get("/scan/files/{file_id}", response_model=schemas.FileDetails, tags=["files"])
def get_file(file_id: str, db: Session = Depends(get_db)): # declare with the type Session (imported directly from SQLAlchemy) and dependency 
    db_file = crud.get_file(db, file_id=id) # get crud here
    if db_file is None:
        raise HTTPException(status_code=404, detail="File not found")
    return db_file

# execution parents for files
@projectapi.get("/scan/files/{file_id}/execution_parents", response_model=List[schemas.ExecutionParents], tags=["execution_parents"])
def get_execution_parents(file_id: str, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    db_execution = crud.get_execution(db, file_id=file_id) # get crud here
    return db_execution



# file with execution_parents: 43239bce0a3200c5d61d968f8e130dbaa3bf987e02417d49191c72bbf1636d4e, b0f476d3f63bf6c0294baa40e1e1a18933a0ee787b6077675b6073c1c1a7b7a4, 92ba324f390c6a09feaf42d88591c7481fe432ed9a58822efebda0a7bca170db
# cd56643dc3a657ad83b8edbe9f607a572643db0d7ea7376bb86b569c38f82cee
# file without execution_parents: 7d5d737c4ed73caaa9c9ac37ffc8926db74549185212800138202ad9f29b1412

