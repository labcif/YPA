import argparse
import sys
import time
import sqlite3
import json
# It's only used for formatting, so we don't want to crash due to it.
try:
    from lxml import etree
except ImportError:
    pass
import re

PRAGMA_USER_VERSION = 'PRAGMA user_version'
USER_VERSION = 'user_version'
QUERY_ASSETS = 'SELECT RecordId, PrimaryId, nh.ParentId, AssetKey, AssetValue, WNSId, HandlerType, WNFEventName, \
                    SystemDataPropertySet, nh.CreatedTime, nh.ModifiedTime, n.Payload, n.Type, n.ArrivalTime, \
                    n.PayloadType, n.ExpiryTime \
                FROM NotificationHandler nh  \
                LEFT JOIN HandlerAssets ha ON ha.HandlerId = nh.RecordId \
                LEFT JOIN Notification n ON nh.RecordId = n.HandlerId \
                ORDER BY RecordId'
ASSETS = "assets"

def main(args):
    start_time = time.time()
    path = args.path
    jpath = args.json
    if not path:
        print("Path is required.")
        exit()
    if not jpath:
        print("JSON result path is required.")
        exit()
    data = process_db(path)
    print(str(data))
    with open(jpath, 'w') as fp:
        json.dump(data, fp, indent=4)
    total_time = round(time.time() - start_time, 2)
    print('Elapsed time: ' + str(total_time) + 's')
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast('NotifAnalyzer', f'Finished processing notifications! Took {str(total_time)}s', duration = None)
    except Exception as e:
        pass

def process_db(file):
    db_info = {}
    try:
        db_conn = sqlite3.connect(file)
        db_conn.row_factory = sqlite3.Row
        c = db_conn.cursor()
        c.execute(PRAGMA_USER_VERSION)
        db_info[USER_VERSION] = c.fetchone()[0]
        c.execute(QUERY_ASSETS)
        asset_data = [dict(row) for row in c.fetchall()]
        db_info[ASSETS] = process_assets(asset_data)
    except Exception as e:
        db_info = None
        print(str(e))
    finally:
        c.close()
        db_conn.close()
    return db_info

def process_assets(assets):
    processed_assets = {}
    for asset in assets:
        id = asset["RecordId"]
        if id in processed_assets:
            # Not new asset
            process_asset_key(asset, processed_assets[id])
            process_notification(asset, dict_asset)
        else:
            # New asset
            dict_asset = {}
            dict_asset["HandlerId"] = id
            dict_asset["HandlerPrimaryId"] = asset["PrimaryId"]
            dict_asset["ParentId"] = asset["ParentId"]
            dict_asset["WNSId"] = asset["WNSId"]
            dict_asset["HandlerType"] = asset["HandlerType"]
            dict_asset["WNFEventName"] = asset["WNFEventName"]
            dict_asset["SystemDataPropertySet"] = asset["SystemDataPropertySet"]
            dict_asset["CreatedTime"] = asset["CreatedTime"]
            dict_asset["ModifiedTime"] = asset["ModifiedTime"]
            dict_asset["OtherAssets"] = []
            dict_asset["Notifications"] = []
            process_asset_key(asset, dict_asset)
            process_notification(asset, dict_asset)

            processed_assets[id] = dict_asset

    return processed_assets

def process_asset_key(asset, dict_asset):
    if "AssetKey" not in asset:
        return
    asset_key = asset["AssetKey"]
    if asset_key == "DisplayName":
        dict_asset["AppName"] = asset["AssetValue"]
    elif asset_key:
        asset_pair = {asset_key: asset["AssetValue"]}
        if asset_pair not in dict_asset["OtherAssets"]:
            dict_asset["OtherAssets"].append(asset_pair)
        
def process_notification(asset, dict_asset):
    if "Payload" not in asset:
        return
    payload = asset["Payload"]
    if payload:
        try:
            root = etree.fromstring(payload)
            payload = etree.tostring(root, pretty_print=True).decode()
        except Exception as e:
            print("Failed to format XML due to " + str(e) + ". Falling back newline after '>'")
            try:
                payload = re.sub(r'(>)', r'\1\n', payload.decode())
            except Exception as e:
                print("Failed to format XML due to " + str(e) + ". Falling back to Payload as string")
                payload = str(payload)
        notif = {
            "Payload": payload,
            "Type": asset["Type"],
            "ExpiryTime": asset["ExpiryTime"],
            "ArrivalTime": asset["ArrivalTime"],
            "PayloadType": asset["PayloadType"]
            }
        dict_asset["Notifications"].append(notif)

def setup_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--path', type=str, help='Path to Notifications DB (wpndatabase.db)')
    parser.add_argument('-j', '--json', type=str, help='Path to result file in JSON')
    return parser.parse_args()

if __name__ == "__main__":
    args = setup_args()
    main(args)