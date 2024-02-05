import json, datetime
from pqdm.threads import pqdm
import pandas as pd
import gc
from pymongo import MongoClient

# Normalize
def start_dag(site):
    # Normalize
    alerts = site["alerts"]
    normalize_alert = {alert["alertRef"]: alert for alert in alerts}
    site["alerts"] = normalize_alert
    alerts = site["alerts"]

    def start_dag_each_vul(key):
        # Mapping each vulnerability to CVSS
        alertRef_column = alertRef_CVSS["alertRef"]
        if key in alertRef_column.values: 
            row_index = alertRef_column[alertRef_column == key].index[0]
            alerts[key]["CVSS"] = alertRef_CVSS.at[row_index, "Base_CVSS_Score"]
        # Classify each vulnerability to OWASP TOP 10
        alertRef_column_group = alertRef_OwaspTop10["alertRef"]
        if key in alertRef_column_group.values:
            row_index = alertRef_column_group[alertRef_column_group == key].index[0]
            alerts[key]["OwaspTop10Group"] = alertRef_OwaspTop10.at[row_index, "group"]
        # Mapping each vulnerablity to organization cvss based on OWASP TOP 10
        group_column = OwaspTop10_OrgCVSS["group"]
        getOwaspTop10GroupKey = alerts[key].get("OwaspTop10Group", "none")
        if getOwaspTop10GroupKey != "none":
            if alerts[key]["OwaspTop10Group"] in group_column.values:
                row_index = group_column[group_column == alerts[key]["OwaspTop10Group"]].index[0]
                alerts[key]["OrgCVSS"] = OwaspTop10_OrgCVSS.at[row_index, "OrgCVSS"]
        # Calulate New cvss score and risk level
        getCVSSKey = alerts[key].get("CVSS", "none")
        getOwaspTop10GroupKey = alerts[key].get("OwaspTop10Group", "none")
        getOrgCVSSKey = alerts[key].get("OrgCVSS", "none")
        if(getCVSSKey != "none" and getOwaspTop10GroupKey != "none" and getOrgCVSSKey != "none"):
            alerts[key]["NewCVSS"] = round((float(alerts[key]["CVSS"]) + float(alerts[key]["OrgCVSS"]))/ 2, 2)
            if(alerts[key]["NewCVSS"] >= 9.0 and alerts[key]["NewCVSS"] <= 10):
                alerts[key]["Risk"] = "Critical"
            elif(alerts[key]["NewCVSS"] >= 7.0 and alerts[key]["NewCVSS"] <= 8.9):
                alerts[key]["Risk"] = "High"
            elif(alerts[key]["NewCVSS"] >= 4.0 and alerts[key]["NewCVSS"] <= 6.9):
                alerts[key]["Risk"] = "Medium"
            elif(alerts[key]["NewCVSS"] >= 0.0 and alerts[key]["NewCVSS"] <= 3.9):
                alerts[key]["Risk"] = "Low"

    # Execute DAG for each vulnerability
    start_time_for_al_1_2 = datetime.datetime.now()
    pqdm(alerts, start_dag_each_vul, n_jobs=len(alerts))
    end_time_for_al_1_2 = datetime.datetime.now()
    with open('./evaluation/DyVAM_performance/Algorithm_1-2_performance/Algorithm_1-2_performance.txt', "a") as file:
        file.write(f"{end_time_for_al_1_2 - start_time_for_al_1_2}" + "\n")
        
def save_mongo_db(site):
    print()
    site["generated_time"] = datetime.datetime.now()
    # with open("./example_result/DyVAM/site.json", "w") as file:
    #     file.write(json.dumps(site))
    client = MongoClient('mongodb://localhost:27017/')
    db = client['DyVAM_Database']
    collection = db['dyvam_collection']
    data_to_insert = site
    result = collection.insert_one(data_to_insert)
    # print(f"Inserted document ID: {result.inserted_id}")

if __name__ == "__main__":
    # Start
    gc.collect()
    starting_time = datetime.datetime.now()
    # Data collectin
    with open("./data/num_record/web_vul_10.json", "r") as file:
        web_vul = json.load(file)                                        # get website vulnerability
    alertRef_CVSS = pd.read_csv("./data/alertRef_CVSS.csv")              # get cvss of each vulnerability
    alertRef_OwaspTop10 = pd.read_csv("./data/alertRef_OwaspTop10.csv")  # get owasp top 10 of each vulnerability
    OwaspTop10_OrgCVSS = pd.read_csv("./data/OwaspTop10_OrgCVSS.csv")    # get cvss of each owasp top 10
    sites = web_vul["site"]     # Sites contain 10 website

    # Start DAG
    pqdm(sites, start_dag, n_jobs=len(sites))
    pqdm(sites, save_mongo_db, n_jobs=len(sites))

    finishing_time = datetime.datetime.now()
    with open('./evaluation/DyVAM_performance/Dag_generatation_performance/Dag_generation_performance.txt', "a") as file:
        file.write(f"{finishing_time - starting_time}" + "\n")
    gc.collect()