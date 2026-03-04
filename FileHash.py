import pandas as pd
import requests
import datetime
import os

VT_API_KEYS = [
    os.getenv("VT_KEY_1"),
    os.getenv("VT_KEY_2"),
    os.getenv("VT_KEY_3"),
    os.getenv("VT_KEY_4")
]

def convert_timestamp(ts):
    """Converts Unix timestamps into human-readable date strings."""
    try:
        if ts:
            return datetime.datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    return ""

def lookup_hash_alienvault(file_hash):
    """Queries AlienVault OTX for file indicators."""
    result = {
        "AV_Hash-MD5": "", "AV_Hash-SHA1": "", "AV_Hash-SHA256": file_hash,
        "AV_File Type": "", "AV_Magic": "", "AV_First Seen In The Wild": "",
        "AV_Detection count": 0, "AV_Name1": ""
    }
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/file/{file_hash}/general"
    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(otx_url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        file_info = data.get("file_info", {})
        result.update({
            "AV_Hash-MD5": file_info.get("md5", ""),
            "AV_Hash-SHA1": file_info.get("sha1", ""),
            "AV_File Type": file_info.get("file_type", ""),
            "AV_Magic": file_info.get("magic", ""),
            "AV_First Seen In The Wild": data.get("first_seen", ""),
            "AV_Detection count": data.get("pulse_info", {}).get("count", 0),
            "AV_Name1": file_info.get("file_name", "")
        })
    return result

def lookup_hash_virustotal(file_hash, vt_api_key):
    """Queries VirusTotal API v3 for file attributes."""
    result = {
        "VT_Hash-MD5": "", "VT_Hash-SHA1": "", "VT_Hash-SHA256": file_hash,
        "VT_File Type": "", "VT_Magic": "", "VT_Creation Time": "",
        "VT_First Submission": "", "VT_Last Submission": "", "VT_Last Analysis": "",
        "VT_Name1": "", "VT_Name2": "", "VT_Name3": "", "VT_Detection count": 0
    }
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    response = requests.get(vt_url, headers=headers)
    
    if response.status_code == 200:
        attributes = response.json().get("data", {}).get("attributes", {})
        names = attributes.get("names", [])
        result.update({
            "VT_Hash-MD5": attributes.get("md5", ""),
            "VT_Hash-SHA1": attributes.get("sha1", ""),
            "VT_File Type": attributes.get("type_description", ""),
            "VT_Magic": attributes.get("magic", ""),
            "VT_Creation Time": convert_timestamp(attributes.get("creation_date")),
            "VT_First Submission": convert_timestamp(attributes.get("first_submission_date")),
            "VT_Last Submission": convert_timestamp(attributes.get("last_submission_date")),
            "VT_Last Analysis": convert_timestamp(attributes.get("last_analysis_date")),
            "VT_Name1": names[0] if len(names) > 0 else "",
            "VT_Name2": names[1] if len(names) > 1 else "",
            "VT_Name3": names[2] if len(names) > 2 else "",
            "VT_Detection count": attributes.get("last_analysis_stats", {}).get("malicious", 0)
        })
    return result

def lookup_hash_combined(file_hash, vt_api_key):
    """Consolidates data and assigns a threat verdict."""
    av_data = lookup_hash_alienvault(file_hash)
    vt_data = lookup_hash_virustotal(file_hash, vt_api_key)
    
    combined = {
        "Detection count": max(vt_data.get("VT_Detection count", 0), av_data.get("AV_Detection count", 0)),
        "Hash-MD5": vt_data.get("VT_Hash-MD5") or av_data.get("AV_Hash-MD5"),
        "Hash-SHA1": vt_data.get("VT_Hash-SHA1") or av_data.get("AV_Hash-SHA1"),
        "Hash-SHA256": vt_data.get("VT_Hash-SHA256") or av_data.get("AV_Hash-SHA256"),
        "File Type": vt_data.get("VT_File Type") or av_data.get("AV_File Type"),
        "Verdict": "Malicious" if max(vt_data.get("VT_Detection count", 0), av_data.get("AV_Detection count", 0)) >= 3 else "Benign"
    }
    return combined

def process_hashes(csv_file):
    """Reads hashes from CSV and manages API key rotation."""
    df = pd.read_csv(csv_file, header=None)
    hash_list = [str(val).strip() for val in df.iloc[885:, 1] if not pd.isna(val) and str(val).strip() != ""]
    
    results = []
    for idx, file_hash in enumerate(hash_list):
        key_index = (idx // 220) % len(VT_API_KEYS)
        data = lookup_hash_combined(file_hash, VT_API_KEYS[key_index])
        results.append(data)
        
    return pd.DataFrame(results)

def main():
    csv_file = "hashes(Sheet1).csv"
    df_results = process_hashes(csv_file)
    df_results.to_csv("results.csv", index=False)
    df_results.to_excel("results.xlsx", index=False)
    print("Results saved to results.csv and results.xlsx.")

if __name__ == "__main__":
    main()