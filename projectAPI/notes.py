# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# notes: if you want to change your webpage -> title="My API Project", version="1.0"
# notes : to change your operation id -> operation_id="" under the @projectapi.get line

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# = Query(..., regex="^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# @projectapi.exception_handler(StarletteHTTPException)
# async def http_exception_handler(request, exc):
#     return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

# @projectapi.exception_handler(RequestValidationError)
# async def validation_exception_handler(request, exc):
#     return PlainTextResponse(str(exc), status_code=400)

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# relationships (model.py)

# domain_ip = relationship("CommunicatingFiles", back_populates="communicating") # relationships: contain values from other tables related to this
# domain_ip = relationship("ReferringFiles", back_populates="referring")
# communicating = relationship("DomainIP", back_populates="domain_ip")
# # referring = relationship("DomainIP", back_populates="domain_ip")
# file_items = relationship("ExecutionParents", back_populates="execution")
# execution = relationship("File", back_populates="file_items")

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# IP ADDRESSES (main.py)
# # ip addresses
# @projectapi.get("/ip_addresses/{ip_id}", response_model=schemas.DomainIP, tags=["ip_addresses"])
# def get_ip_address(ip_id: str = Query(..., regex="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"), db: Session = Depends(get_db)):
#     db_ip = crud.get_ip(db, ip_id=ip_id)
#     if db_ip is None:
#         raise HTTPException(status_code=418, detail="Domain not found")
#     return db_ip

# # communicating files for ip addresses
# @projectapi.get("/ip_addresses/{ip_id}/communicating_files", response_model=schemas.CommunicatingFiles, tags=["communicating_files"])
# def get_ip_communicating_files(ip_id: str, db: Session = Depends(get_db)):
#     db_ipcommunicating_files = crud.get_ipcommunicating(db, ip_id=ip_id)
#     if db_ipcommunicating_files is None:
#         raise HTTPException(status_code=418, detail="Domain not found")
#     return db_ipcommunicating_files

# # referring files for ip addresses
# @projectapi.get("/ip_addresses/{ip_id}/referring_files", response_model=schemas.ReferringFiles, tags=["referring_files"])
# def get_ip_referring_files(ip_id: str, db: Session = Depends(get_db)):
#     db_ipreferring_files = crud.get_ipreferring(db, ip_id=ip_id)
#     if db_ipreferring_files is None:
#         raise HTTPException(status_code=418, detail="Domain not found")
#     return db_ipreferring_files

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# (main.py) 

# if db_communicating is None:
#     raise HTTPException(status_code=404, detail="Communicating Files not found")  
# else:

# if db_referring is None:
#     raise HTTPException(status_code=404, detail="Referring Files not found")
# else:

# if db_execution is None:
#     raise HTTPException(status_code=404, detail="Execution Parents not found")
# else:

# raise HTTPException(status_code=404, detail="Since File is not found, there will be no Execution Parents as well.")

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# IP ADDRESSES (crud.py)
# def get_ip(db: Session, ip_id: str): # read ip address details by ip_id
#     return db.query(models.DomainIP).filter(models.DomainIP.id == ip_id).first()
# # def get_ipcommunicating(db: Session, ip_id: str): # read ip address's communicating files by ip_id
#     return db.query(models.CommunicatingFiles).filter(models.CommunicatingFiles.id == ip_id).first()

# def get_ipreferring(db: Session, ip_id: str): # read ip address's referring files by ip_id
#     return db.query(models.ReferringFiles).filter(models.ReferringFiles.id == ip_id).first() 

# ------------------------------------------------------------------------------------------------------------------------------------------------- #

# # domains
# @projectapi.get("/scan/domain_ip/{id}", response_model=schemas.DomainIP, tags=["domains_ip"])
# def get_domain_or_ip(id: str, db: Session = Depends(get_db)): # declare with the type Session (imported directly from SQLAlchemy) and dependency 
#     db_domain_ip = crud.get_domain_ip(db, id=id) # get crud here
#     if db_domain_ip is None:    # logic function
#         print("Please wait...")
#         regex = str("([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}") # for domain, it is a regex to differentiate domains and IP addresses
#         if re.match(regex, id) is not None: # if input (x) and the regex match, it will run the domain section
#             # domain_scans
#             url = 'https://www.virustotal.com/api/v3/domains/' + id
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'}) # you can change your api-key in here
#             response_dict = json.loads(response.text)

#             # communicating_files
#             url = 'https://www.virustotal.com/api/v3/domains/' + id + '/communicating_files'
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
#             response_communicating_dict = json.loads(response.text)

#             # referring_files
#             url = 'https://www.virustotal.com/api/v3/domains/' + id + '/referrer_files'
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
#             response_referring_dict = json.loads(response.text)

#             try:
#                 conn = psycopg2.connect(database='VirusTotal', user='postgres', password='postgres', host='127.0.0.1', port='5432')

#             except:
#                 print("I am unable to connect to the database.")

#             #cursor
#             cur = conn.cursor()

#             # domain_scans
#             # getting data from the dictionary list saved with the json data
#             domain_id = response_dict['data']['id']
#             domain_date = response_dict['data']['attributes']['whois_date']
#             domain_type = response_dict['data']['type']
#             domain_harmless_score = response_dict['data']['attributes']['last_analysis_stats']['harmless']
#             domain_malicious_score = response_dict['data']['attributes']['last_analysis_stats']['malicious']
#             domain_suspicious_score = response_dict['data']['attributes']['last_analysis_stats']['suspicious']
#             domain_timeout_score = response_dict['data']['attributes']['last_analysis_stats']['timeout']
#             domain_undetected_score = response_dict['data']['attributes']['last_analysis_stats']['undetected']
#             domainDate = datetime.fromtimestamp(domain_date).strftime('%Y-%m-%d %I:%M:%S')
#             domain_score = str(domain_malicious_score + domain_suspicious_score) + "/" + str(domain_harmless_score + domain_malicious_score + domain_suspicious_score + domain_timeout_score + domain_undetected_score)

#             if domain_malicious_score + domain_suspicious_score >= 25:
#                 domain_severity = "High"

#             elif domain_malicious_score + domain_suspicious_score >= 15:
#                 domain_severity = "Medium"

#             else:
#                 domain_severity = "Low"

#             domain_records = (domain_id, domain_type, domain_score, domain_severity, domainDate)

#             # prepared statement for domain_ip_scans
#             cur.execute(
#                 "PREPARE domain_request AS "
#                 "INSERT INTO domain_ip_scans VALUES ($1, $2, $3, $4, $5)")
#             cur.execute("EXECUTE domain_request (%s, %s, %s, %s, %s)", domain_records) # %s for string
#             cur.execute("DEALLOCATE domain_request")
#             conn.commit()

#             # communicating_files
#             # getting data from the dictionary list saved with the json data
#             x = 0
#             while x != len(response_communicating_dict['data']):
#                 communicating_id = response_communicating_dict['data'][x]['id']
#                 communicating_date = response_communicating_dict['data'][x]['attributes']['last_submission_date']
#                 communicating_harmless_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
#                 communicating_malicious_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
#                 communicating_suspicious_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
#                 communicating_timeout_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
#                 communicating_undetected_score = response_communicating_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
#                 communicating_type = response_communicating_dict['data'][x]['attributes']['type_description']
#                 communicating_name = response_communicating_dict['data'][x]['attributes']['names']
#                 date_time = datetime.fromtimestamp(communicating_date).strftime('%Y-%m-%d %I:%M:%S')
#                 communicating_score = str(communicating_malicious_score + communicating_suspicious_score) + "/" + str(communicating_harmless_score + communicating_malicious_score + communicating_suspicious_score + communicating_timeout_score + communicating_undetected_score)
#                 communicating_name_obj = str(communicating_name)[1:-1]

#                 if communicating_malicious_score + communicating_suspicious_score >= 25:
#                     communicating_severity = "High"

#                 elif communicating_malicious_score + communicating_suspicious_score >= 15:
#                     communicating_severity = "Medium"  

#                 else:
#                     communicating_severity = "Low"

#                 # prepared statement for communicating_files
#                 communicating_records = (communicating_id, domain_id, date_time, communicating_score, communicating_severity, communicating_type, communicating_name_obj)
#                 cur.execute(
#                     "PREPARE communicating_request AS "
#                     "INSERT INTO communicating_files VALUES ($1, $2, $3, $4, $5, $6, $7)")
#                 cur.execute("EXECUTE communicating_request (%s, %s, %s, %s, %s, %s, %s)", communicating_records)
#                 cur.execute("DEALLOCATE communicating_request")
#                 conn.commit()

#                 x+=1

#             # referring_files
#             # getting data from the dictionary list saved with the json data
#             x = 0
#             while x != len(response_referring_dict['data']):
#                 referring_id = response_communicating_dict['data'][x]['id']
#                 referring_date = response_referring_dict['data'][x]['attributes']['last_submission_date']
#                 referring_harmless_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
#                 referring_malicious_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
#                 referring_suspicious_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
#                 referring_timeout_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
#                 referring_undetected_score = response_referring_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
#                 referring_type = response_referring_dict['data'][x]['attributes']['type_description']
#                 referring_name = response_referring_dict['data'][x]['attributes']['names']
#                 date_time = datetime.fromtimestamp(referring_date).strftime('%Y-%m-%d %I:%M:%S')
#                 referring_score = str(referring_malicious_score + referring_suspicious_score) + "/" + str(referring_harmless_score + referring_malicious_score + referring_suspicious_score + referring_timeout_score + referring_undetected_score)
#                 referring_name_obj = str(referring_name)[1:-1]

#                 if referring_malicious_score + referring_suspicious_score >= 25:
#                     referring_severity = "High"

#                 elif referring_malicious_score + referring_suspicious_score >= 15: 
#                     referring_severity = "Medium"
                    
#                 else:
#                     referring_severity = "Low"

#                 # prepared statement for referring_files
#                 referring_records = (referring_id, domain_id, date_time, referring_score, referring_severity, referring_type, referring_name_obj)
#                 cur.execute(
#                     "PREPARE referring_request AS "
#                     "INSERT INTO referring_files VALUES ($1, $2, $3, $4, $5, $6, $7)"
#                 )
#                 cur.execute("EXECUTE referring_request (%s, %s, %s, %s, %s, %s, %s)", (referring_records))
#                 cur.execute("DEALLOCATE referring_request")
#                 conn.commit()

#                 x+=1

#         else: # if the regex and the input does not match (e.g. IP address), it will run the IP section
#             # ip_scans
#             url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'}) # you can change your api-key in here
#             response_ip_dict = json.loads(response.text)

#             # communicating_files
#             url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id + '/communicating_files'
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
#             response_ipcomms_dict = json.loads(response.text)

#             # referring_files
#             url = 'https://www.virustotal.com/api/v3/ip_addresses/' + id + '/referrer_files'
#             response = requests.get(url, headers={'x-apikey': '7eee67229628b5e21b740b91926cadb65c606a672365363b50a578073ea65f5f'})
#             response_ipreferring_dict = json.loads(response.text)

#             try:
#                 conn = psycopg2.connect(database='VirusTotal', user='postgres', password='postgres', host='127.0.0.1', port='5432')

#             except:
#                 print("I am unable to connect to the database.")

#             #cursor
#             cur = conn.cursor()

#             # ip_scans
#             # getting data from the dictionary list saved with the json data
#             ip_id = response_ip_dict['data']['id']
#             ip_date = response_ip_dict['data']['attributes']['whois_date']
#             ip_type = response_ip_dict['data']['type']
#             ip_harmless_score = response_ip_dict['data']['attributes']['last_analysis_stats']['harmless']
#             ip_malicious_score = response_ip_dict['data']['attributes']['last_analysis_stats']['malicious']
#             ip_suspicious_score = response_ip_dict['data']['attributes']['last_analysis_stats']['suspicious']
#             ip_timeout_score = response_ip_dict['data']['attributes']['last_analysis_stats']['timeout']
#             ip_undetected_score = response_ip_dict['data']['attributes']['last_analysis_stats']['undetected']
#             ipDate = datetime.fromtimestamp(ip_date).strftime('%Y-%m-%d %I:%M:%S')
#             ip_score = str(ip_malicious_score + ip_suspicious_score) + "/" + str(ip_harmless_score + ip_malicious_score + ip_suspicious_score + ip_timeout_score + ip_undetected_score)

#             if ip_malicious_score + ip_suspicious_score >= 25:
#                 ip_severity = "High"

#             elif ip_malicious_score + ip_suspicious_score >= 15:
#                 ip_severity = "Medium"

#             else:
#                 ip_severity = "Low"

#             ip_records = (ip_id, ip_type, ip_score, ip_severity, ipDate)
            
#             # prepared statements for domain_ip_scans
#             cur.execute(
#                 "PREPARE ip_request AS "
#                 "INSERT INTO domain_ip_scans VALUES ($1, $2, $3, $4, $5)"
#             )
#             cur.execute("EXECUTE ip_request (%s, %s, %s, %s, %s)", (ip_records)) #%s for string
#             cur.execute("DEALLOCATE ip_request")
#             conn.commit()

#             # ip_communicating_files
#             # getting data from the dictionary list saved with the json data
#             x = 0
#             while x != len(response_ipcomms_dict['data']):
#                 ipcomms_id = response_ipcomms_dict['data'][x]['id']
#                 ipcomms_date = response_ipcomms_dict['data'][x]['attributes']['last_submission_date']
#                 ipcomms_harmless_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
#                 ipcomms_malicious_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
#                 ipcomms_suspicious_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
#                 ipcomms_timeout_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
#                 ipcomms_undetected_score = response_ipcomms_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
#                 ipcomms_type = response_ipcomms_dict['data'][x]['attributes']['type_description']
#                 ipcomms_name = response_ipcomms_dict['data'][x]['attributes']['names']
#                 date_time = datetime.fromtimestamp(ipcomms_date).strftime('%Y-%m-%d %I:%M:%S')
#                 ipcomms_score = str(ipcomms_malicious_score + ipcomms_suspicious_score) + "/" + str(ipcomms_harmless_score + ipcomms_malicious_score + ipcomms_suspicious_score + ipcomms_timeout_score + ipcomms_undetected_score)
#                 ipcomms_name_obj = str(ipcomms_name)[1:-1]

#                 if ipcomms_malicious_score + ipcomms_suspicious_score >= 25:
#                     ipcomms_severity = "High"

#                 elif ipcomms_malicious_score + ipcomms_suspicious_score >= 15:
#                     ipcomms_severity = "Medium"  

#                 else:
#                     ipcomms_severity = "Low"

#                 # prepared statement for communicating_files
#                 ipcomms_records = (ipcomms_id, ip_id, date_time, ipcomms_score, ipcomms_severity, ipcomms_type, ipcomms_name_obj)
#                 cur.execute(
#                     "PREPARE ipcommunicating_request AS "
#                     "INSERT INTO communicating_files VALUES ($1, $2, $3, $4, $5, $6, $7)")
#                 cur.execute("EXECUTE ipcommunicating_request (%s, %s, %s, %s, %s, %s, %s)", ipcomms_records)
#                 cur.execute("DEALLOCATE ipcommunicating_request")
#                 conn.commit()

#                 x+=1

#             # ip_referring_files
#             # getting data from the dictionary list saved with the json data
#             x = 0
#             while x != len(response_ipreferring_dict['data']):
#                 ipreferring_id = response_ipreferring_dict['data'][x]['id']
#                 ipreferring_date = response_ipreferring_dict['data'][x]['attributes']['last_submission_date']
#                 ipreferring_harmless_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['harmless']
#                 ipreferring_malicious_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['malicious']
#                 ipreferring_suspicious_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['suspicious']
#                 ipreferring_timeout_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['timeout']
#                 ipreferring_undetected_score = response_ipreferring_dict['data'][x]['attributes']['last_analysis_stats']['undetected']
#                 ipreferring_type = response_ipreferring_dict['data'][x]['attributes']['type_description']
#                 ipreferring_name = response_ipreferring_dict['data'][x]['attributes']['names']
#                 date_time = datetime.fromtimestamp(ipreferring_date).strftime('%Y-%m-%d %I:%M:%S')
#                 ipreferring_score = str(ipreferring_malicious_score + ipreferring_suspicious_score) + "/" + str(ipreferring_harmless_score + ipreferring_malicious_score + ipreferring_suspicious_score + ipreferring_timeout_score + ipreferring_undetected_score)
#                 ipreferring_name_obj = str(ipreferring_name)[1:-1]

#                 if ipreferring_malicious_score + ipreferring_suspicious_score >= 25:
#                     ipreferring_severity = "High"

#                 elif ipreferring_malicious_score + ipreferring_suspicious_score >= 15: 
#                     ipreferring_severity = "Medium"
                    
#                 else:
#                     ipreferring_severity = "Low"

#                 # prepared statement for referring_files
#                 ipreferring_records = (ipreferring_id, ip_id, date_time, ipreferring_score, ipreferring_severity, ipreferring_type, ipreferring_name_obj)
#                 cur.execute(
#                     "PREPARE ipreferring_request AS "
#                     "INSERT INTO referring_files VALUES ($1, $2, $3, $4, $5, $6, $7)"
#                 )
#                 cur.execute("EXECUTE ipreferring_request (%s, %s, %s, %s, %s, %s, %s)", (ipreferring_records))
#                 cur.execute("DEALLOCATE ipreferring_request")
#                 conn.commit()

#                 x+=1

#         # close the cursor
#         cur.close()

#         # close the connection
#         conn.close()

#         db_domain_ip = crud.get_domain_ip(db, id=id)
#         return db_domain_ip

#     else:
#         return db_domain_ip



# # get all information for domains and ip addresses
# @projectapi.get("/scan/domain_ip/{id}/all_information", response_model=List[schemas.DomainIP_Comms_Referr], tags=["all_information_for_domain_or_ip"])
# def get_all_information_for_domain_or_ip(id: str, db: Session = Depends(get_db)):
#     db_all_information_for_domain_or_ip = crud.get_all_domainipinfo(db, id=id) # get crud here
#     return db_all_information_for_domain_or_ip