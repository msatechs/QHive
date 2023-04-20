#!/usr/bin/env python3
import requests
import json
from urllib.parse import urljoin
import time
import urllib3
import sys
import logging
from hashlib import md5
from configparser import ConfigParser
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#?########################################### CONFIG ##############################################################

#! file name
fnafr=sys.argv[0].split('.')[0]

##! Config file path
conf_file = fnafr+".conf"

config = ConfigParser()
config.read(conf_file)

try:
    ClientInfo = config["ClientInfo"]
    SOCInfo = config["SOCInfo"]
    ConfigInfo = config["ConfigInfo"]
    LogInfo = config["LogInfo"]
except KeyError:
    sys.exit("Error found in the configuration file.")
    
#? Client
client = ClientInfo["client"]

#? URLS
TheHive_url = SOCInfo["Thehive_url"]
Qradar_url = ClientInfo["Qradar_url"]

#? Tokens and APIs
QRadar_token = ClientInfo["QRadar_token"]
H_API_KEY = SOCInfo["H_API_KEY"] #! qhive@brm

#? Number of offenses to be imported
nbr_offenses = int(ConfigInfo["nbr_offenses"])

#? Number of seconds between offense api requests
nbr_sec = int(ConfigInfo["nbr_sec"])

#? Number of seconds between api timeouts
nbr_sec_timeout = int(ConfigInfo["nbr_sec_timeout"])

#? Maximum number of observables to get
limit_art = int(ConfigInfo["limit_art"])

#* Dict name
id_dict_f = LogInfo["id_dict_f"]

#* log file
log_file = LogInfo["log_file"]

#* errors log file
err_log_file = LogInfo["err_log_file"]

#?########################################### CONFIG ##############################################################

#! Logging
log = logging.getLogger()
logformat= '%(asctime)s - %(message)s'
log_formatter = logging.Formatter(logformat, datefmt='%d-%b-%y %H:%M:%S')

#! Log info
log_info = logging.FileHandler(log_file, mode='a')
log_info.setLevel(logging.INFO)
log_info.setFormatter(log_formatter)
log.addHandler(log_info)

#! Log errors
log_err = logging.FileHandler(err_log_file, mode='a')
log_err.setLevel(logging.ERROR)
log_err.setFormatter(log_formatter)
log.addHandler(log_err)

log.setLevel(logging.INFO)

#! QRADAR API URL
Offense_id_url = '/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId='

#*########################################### FUNCTIONS ################################################################

#! Get alert from QRadar
def get_alert(ssl_ver = True):
    offense_api = '/api/siem/offenses'
    off_range = "items=0-"+str(nbr_offenses-1)
    headers = {'Accept': 'application/json', 'Range': off_range,'Accept-Charset': 'UTF-8', 'SEC': QRadar_token}
    r = requests.get(urljoin(Qradar_url,offense_api), headers=headers, verify = ssl_ver, timeout=5)
    return r
#! Get Q response
def get_Q():
    global offense_json
    try:
        offense_json = json.loads(get_alert(False).content)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_Q()

#! Send alert to TheHive
def post_alert(ssl_ver = True):
    alert_api = '/api/alert'
    AUTH = 'Bearer '+ H_API_KEY
    headers = {'Content_type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': AUTH}
    r = requests.post(urljoin(TheHive_url,alert_api), headers=headers, json=alert, verify = ssl_ver)
    return r

#! update alert in TheHive
def patch_alert(al_id, ssl_ver = True):
    alert_api = '/api/alert/'+str(al_id)
    AUTH = 'Bearer '+ H_API_KEY
    headers = {'Content_type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': AUTH}
    r = requests.patch(urljoin(TheHive_url,alert_api), headers=headers, json=alert, verify = ssl_ver)
    return r

#! Add artifact to alert
def post_art(al_id, art, ssl_ver = True):
    art_api = f"/api/alert/{al_id}/artifact"
    AUTH = 'Bearer '+ H_API_KEY
    headers = {'Content_type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': AUTH}
    r = requests.post(urljoin(TheHive_url,art_api), headers=headers, json=art, verify = ssl_ver)
    return r

#! Get ids
def get_id(rel, id_add, extr = "", ssl_ver = True):
    src_dest_api = f"/api/siem/{rel}/{id_add}{extr}"
    headers = {'Accept': 'application/json','Accept-Charset': 'UTF-8', 'SEC': QRadar_token}
    r = requests.get(urljoin(Qradar_url,src_dest_api), headers=headers, verify = ssl_ver, timeout=5)
    return r

#! Get src id Response
def get_src_id(idd):
    global get_id_res_json
    try:
        get_id_res_json = json.loads(get_id('source_addresses', "", idd, False).content)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_src_id(idd)

#! Get dest id Response
def get_dst_id(idd):
    global get_id_res_json
    try:
        get_id_res_json = json.loads(get_id('local_destination_addresses', "", idd, False).content)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_dst_id(idd)

#! Get closing reason ids Response
def get_close_id(idd):
    global get_id_res_json
    try:
        get_id_res_json = json.loads(get_id('offense_closing_reasons', "", idd, False).content)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_close_id(idd)

#! Get notes
def get_notes():
    global get_note_list
    try:
        get_note_list = json.loads(get_id('offenses', offense_id, '/notes', False).content)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_notes()

#! Read alert
def read_alert(al_id, ssl_ver = True):
    read_api = f"/api/alert/{str(al_id)}"
    AUTH = 'Bearer '+ H_API_KEY
    headers = {'Content_type': 'application/json', 'Accept-Charset': 'UTF-8', 'Authorization': AUTH}
    r = requests.get(urljoin(TheHive_url,read_api), headers=headers, verify = ssl_ver)
    return r

#! Read alert repeatdly
def get_A(al_id):
    global get_alert_json
    try:
        get_alert_json = read_alert(al_id, False)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as E1:
        if 'No route to host' in str(E1):
            log.critical("No route to host. Retrying after 10 seconds...")
            time.sleep(10)
        else:
            if nbr_sec_timeout > 0:
                log.error(f"{E1}. Retrying after "+str(nbr_sec_timeout)+" seconds...")
            else:
                log.error(f"{E1}. Retrying...")
            time.sleep(nbr_sec_timeout)
        get_A(al_id)
    except json.decoder.JSONDecodeError:
        logging.critical(f"TheHive{client} might be down. Check if it's running")
        time.sleep(nbr_sec_timeout)
        get_A(al_id)

#! Send Alert Updated to QRadar
def update_alert(idd, d, ssl_ver = True):
    q_api = f"/api/siem/offenses/{idd}"
    headers = {'Accept': 'application/json', 'Accept-Charset': 'UTF-8', 'SEC': QRadar_token}
    r = requests.post(urljoin(Qradar_url, q_api), headers=headers, data=d, verify = ssl_ver, timeout=5)
    return r

#! Create note
def up_note(idd, d, ssl_ver = True):
    q_api = f"/api/siem/offenses/{idd}/notes"
    headers = {'Accept': 'application/json', 'Accept-Charset': 'UTF-8', 'SEC': QRadar_token}
    r = requests.post(urljoin(Qradar_url, q_api), headers=headers, data=d, verify = ssl_ver)
    return r

#*########################################### FUNCTIONS ################################################################

#! Function to be executed every nbr_sec
def Live_Fetch():
    global alert, src_id, dest_id, close_id, offense_id, get_note_list
    #! Get alert from QRadar
    get_Q()
    try:
        offense_json['http_response']
        if offense_json['http_response']['code'] == 401:
            log.critical(offense_json['http_response']['message'])
            sys.exit()
    except:
        pass
    if len(offense_json) == 0:
        log.info("No alerts were found")
    elif "You are unauthorized" in json.dumps(offense_json):
        log.error(offense_json)

    else:
        log.info(f"Batch of alerts acquired. Copying {nbr_offenses} alerts from QRadar{client} to TheHive{client}...")
        #! Get response from Qradar
        for single_alert_J in offense_json:
            #! Clean Alert
            alert = {
                'artifacts': None,
                'description': None,
                'severity': None,
                'source': None,
                'sourceRef': None,
                'title': None,
                'tlp': 3,
                'pap': 2,
                'type': None,
                'customFields': None
                }
            offense_id = single_alert_J['id']
            #! Get Log sources
            try:
                if len(single_alert_J['log_sources']) > 1:
                    log_sources = f"Multiple({len(single_alert_J['log_sources'])})"
                elif len(single_alert_J['log_sources']) == 1:
                    log_sources = single_alert_J['log_sources'][0]['name']
                else:
                    log_sources = None
            except KeyError:
                log_sources = None
            #! Get Destination networks
            if len(single_alert_J['destination_networks']) > 1:
                dest_networks = f"Multiple({len(single_alert_J['destination_networks'])})"
            elif len(single_alert_J['destination_networks']) == 1:
                dest_networks = single_alert_J['destination_networks'][0]
            else:
                dest_networks = None
            #! Get source and destination IPs
            if single_alert_J['source_count'] > 1:
                nr_src = True
                source_ip = f"Multiple({single_alert_J['source_count']})"
            elif single_alert_J['source_count'] == 1:
                nr_src = True
                src_id = single_alert_J['source_address_ids'][0]
                get_src_id(src_id)
                source_ip = get_id_res_json['source_ip']
            else:
                nr_src = False
                source_ip = "See QRadar"
            #!
            if single_alert_J['local_destination_count'] > 1:
                nr_dst = True
                destination_ip = f"Multiple({single_alert_J['local_destination_count']})"
            elif single_alert_J['local_destination_count'] == 1:
                nr_dst = True
                dest_id = single_alert_J['local_destination_address_ids'][0]
                get_dst_id(dest_id)
                destination_ip = get_id_res_json['local_destination_ip']
            else:
                nr_dst = False
                destination_ip = "See QRadar"
            #! Get closing reason
            if single_alert_J['closing_reason_id'] != None:
                close_id = single_alert_J['closing_reason_id']
                get_close_id(close_id)
                closing_text = get_id_res_json["text"]
                closing_id = get_id_res_json["id"]
                closing_gl = str(closing_id)+':'+str(closing_text)
            else:
                closing_gl = None
            #! Get note
            get_notes()
            note_l = []
            if len(get_note_list) == 0:
                note = None
            else:
                for n in get_note_list:
                    k = n['note_text'].split('\n')[-1].replace('Notes: ','').strip() + "{"+n['username']+"}"
                    nid = n['id']
                    n_to_add = f"Note {nid}: {k}"
                    note_l.append(n_to_add)
                note = '\n'.join(note_l)
            #! Map Severity
            if single_alert_J['severity'] == 8 or single_alert_J['severity'] == 9 or single_alert_J['severity'] == 10:
                sev = 4
            elif single_alert_J['severity'] == 7 or single_alert_J['severity'] == 6:
                sev = 3
            elif single_alert_J['severity'] == 4 or single_alert_J['severity'] == 5:
                sev = 2
            else:
                sev = 1
            #! Fill alert with Qradar values
            alert['title'] = single_alert_J['description']
            alert['description'] = single_alert_J['description']
            alert['date'] = single_alert_J['start_time']
            alert['type'] = 'QRADAR'
            alert['source'] = single_alert_J['offense_source']
            srcref = f"{client}{urljoin(Qradar_url, Offense_id_url+str(offense_id))}{single_alert_J['first_persisted_time']}"
            alert['sourceRef'] = str(offense_id)+':'+(str(md5(srcref.encode()).hexdigest())).upper()
            alert['severity'] = sev
            alert['customFields'] = {
                "client": {
                    "string": client,
                    "order": 0
                    },
                "trigger-date": {
                    "date": single_alert_J['start_time'],
                    "order": 1
                    },
                "offense-url": {
                    "string" : urljoin(Qradar_url, Offense_id_url)+str(offense_id),
                    "order": 3
                },
                "event-count": {
                    "integer": single_alert_J['event_count'],
                    "order": 14
                    },
                "log-sources": {
                    "string": log_sources,
                    "order": 4
                    },
                "source-network": {
                    "string": single_alert_J['source_network'],
                    "order": 6
                    },
                "destination-networks": {
                    "string": dest_networks,
                    "order": 8
                    },
                "source-ip": {
                    "string": source_ip,
                    "order": 5
                    },
                "destination-ip": {
                    "string": destination_ip,
                    "order": 7
                    },
                "assigned-to": {
                    "string": single_alert_J['assigned_to'],
                    "order": 15
                    },
                "follow-up": {
                    "boolean": single_alert_J['follow_up'],
                    "order": 16
                    },
                "status": {
                    "string": single_alert_J['status'],
                    "order": 17
                    },
                "closing-user": {
                    "string": single_alert_J['closing_user'],
                    "order": 18
                    },
                "closing-time": {
                    "date": single_alert_J['close_time'],
                    "order": 19
                    },
                "closing-reason": {
                    "string": closing_gl,
                    "order": 20
                    },
                "notes": {
                    "string": note,
                    "order": 21
                    },
                "host-os": {
                    "string": "N/A",
                    "order": 12
                    },
                "user-name": {
                    "string": "N/A",
                    "order": 9
                    },
                "process-name": {
                    "string": "N/A",
                    "order": 10
                    },
                "process-signature": {
                    "string": "N/A",
                    "order": 11
                    },
                "original-event": {
                    "string": "N/A",
                    "order": 13
                    },
                "reason": {
                    "string": "N/A",
                    "order": 2
                    }
            }
            #! Create alert
            try:
                Hive_response = post_alert(False)
            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError) as E6:
                if 'No route to host' in str(E6):
                    logging.critical('No route to host. Exiting...')
                    continue
            try:
                J_Hive_response = json.loads(Hive_response.content)
            except UnboundLocalError:
                logging.critical(f"Failed to get a response from TheHive{client}. Check if it's running")
                continue
            except json.decoder.JSONDecodeError:
                logging.critical(f"TheHive{client} might be down. Check if it's running")
                continue
            if Hive_response.status_code == 201:
                alert_id_Hive = J_Hive_response['_id']
                Id_map = {offense_id:alert_id_Hive}
                try:
                    with open(id_dict_f, 'r') as r:
                        id_dict = json.load(r)
                    id_dict.update(Id_map)
                    with open(id_dict_f, 'w') as m:
                        json.dump(id_dict, m)
                except FileNotFoundError:
                    with open(id_dict_f, 'w') as m:
                        json.dump(Id_map, m)
                #! Send Source IP Artifacts
                if nr_src:
                    for i in single_alert_J['source_address_ids'][:limit_art]:
                        get_src_id(i)
                        art_ip = get_id_res_json['source_ip']
                        art_data = {'dataType': 'ip','data': art_ip, 'message': 'Source IP', 'tags':['Source IP']}
                        art_res = post_art(alert_id_Hive, art_data, False)
                        if art_res.status_code == 201:
                            pass
                        elif "Observable already exists" in json.loads(art_res.content)['failure'][0]['message']:
                            pass
                        else:
                            log.error(art_res.content.decode('utf-8'))
                #! Send Destination IP Artifacts
                if nr_dst:
                    for i in single_alert_J['local_destination_address_ids'][:limit_art]:
                        get_dst_id(i)
                        art_ip = get_id_res_json['local_destination_ip']
                        art_data = {'dataType': 'ip','data': art_ip, 'message': 'Destination IP', 'tags':['Destination IP']}
                        art_res = post_art(alert_id_Hive, art_data, False)
                        if art_res.status_code == 201:
                            pass
                        elif "Observable already exists" in json.loads(art_res.content)['failure'][0]['message']:
                            pass
                        else:
                            log.error(art_res.content.decode('utf-8'))
                log.info(f"Creation of Alert {alert_id_Hive} Successful - QRadar offense id: {offense_id}")
            elif "already exist in" in J_Hive_response['message']:
                try:
                    with open(id_dict_f, 'r') as r:
                        id_dict = json.load(r)
                    try:
                        alert_id_Hive = id_dict[str(offense_id)]
                    except KeyError:
                        log.error("Alert exists but Id mapping couldn't be executed")
                        continue
                    #! Check for differences
                    #! Read our alert
                    get_A(alert_id_Hive)
                    read_res = get_alert_json
                    if read_res.status_code != 200:
                        log.error(read_res.content.decode('utf-8'))
                    else:
                        al_cl_usr = json.loads(read_res.content)['customFields']['closing-user']['string']
                        al_cl_reason = json.loads(read_res.content)['customFields']['closing-reason']['string']
                        al_ass = json.loads(read_res.content)['customFields']['assigned-to']['string']
                        al_fol = json.loads(read_res.content)['customFields']['follow-up']['boolean']
                        al_status = json.loads(read_res.content)['customFields']['status']['string']
                        al_notes = json.loads(read_res.content)['customFields']['notes']['string']

                        if single_alert_J['status'] == 'CLOSED':
                            if single_alert_J['assigned_to'] != al_ass or single_alert_J['follow_up'] != al_fol:
                                #! Update assigned to and fup parameters in offense
                                offense_data = {
                                    'assigned_to' : al_ass,
                                    'follow_up' : al_fol
                                }
                                up_res = update_alert(offense_id, offense_data, False)
                                if up_res.status_code == 200:
                                    log.info(f"Changes found in TheHive. Offense {offense_id} successfully updated")
                                    continue
                                else:
                                    log.error(up_res.content.decode('utf-8'))
                        elif single_alert_J['status'] != 'CLOSED' and al_status == 'CLOSED':
                            #! Fix closing reason
                            if al_cl_reason != None:
                                    clrsid = int(al_cl_reason.split(':')[0])
                            else:
                                clrsid = None
                            #! Close Offense
                            offense_data = {
                                'assigned_to' : al_ass,
                                'closing_user' : al_cl_usr,
                                'closing_reason_id' : clrsid,
                                'follow_up' : al_fol,
                                'status' : al_status
                            }
                            up_res = update_alert(offense_id, offense_data, False)
                            if up_res.status_code == 200:
                                log.info(f"Offense {offense_id} successfully closed")
                                #! Fix note
                                cl_reason_2 = al_cl_reason.split(":")[1]
                                note_data = {
                                    'note_text': f"This offense was closed with reason: {cl_reason_2}, {al_notes}",
                                }
                                #! Create note
                                note_res = up_note(offense_id, note_data, False)
                                if note_res.status_code != 201:
                                    log.error(note_res.content.decode('utf-8'))
                                continue
                            else:
                                log.error(up_res.content.decode('utf-8'))
                    #! Patch Alert
                    patch_response = patch_alert(alert_id_Hive, False)
                    if patch_response.status_code == 200:
                        #! Send Source IP Artifacts
                        if nr_src:
                            for i in single_alert_J['source_address_ids'][:limit_art]:
                                get_src_id(i)
                                art_ip = get_id_res_json['source_ip']
                                art_data = {'dataType': 'ip','data': art_ip, 'message': 'Source IP', 'tags':['Source IP']}
                                art_res = post_art(alert_id_Hive, art_data, False)
                                if art_res.status_code == 201:
                                    pass
                                elif "Observable already exists" in json.loads(art_res.content)['failure'][0]['message']:
                                    pass
                                else:
                                    log.error(art_res.content.decode('utf-8'))
                        #! Send Destination IP Artifacts
                        if nr_dst:
                            for i in single_alert_J['local_destination_address_ids'][:limit_art]:
                                get_dst_id(i)
                                art_ip = get_id_res_json['local_destination_ip']
                                art_data = {'dataType': 'ip','data': art_ip, 'message': 'Destination IP', 'tags':['Destination IP']}
                                art_res = post_art(alert_id_Hive, art_data, False)
                                if art_res.status_code == 201:
                                    pass
                                elif "Observable already exists" in json.loads(art_res.content)['failure'][0]['message']:
                                    pass
                                else:
                                    log.error(art_res.content.decode('utf-8'))

                        log.info(f"Update of Alert with Offense id {offense_id} Successful")
                    else:
                        log.error(patch_response.content.decode('utf-8'))
                except FileNotFoundError:
                    log.error("Alert exists but the Id mapping file was not found")
            elif "CustomField" in J_Hive_response['message'] and "not found" in J_Hive_response['message']:
                log.error("Some CustomFields are not defined")
            else:
                log.error(Hive_response.content.decode('utf-8'))

if __name__ == "__main__":
    while True:
        Live_Fetch()
        if nbr_sec > 0:
            log.info(f"Sleeping for {nbr_sec} seconds...")
        time.sleep(nbr_sec)

