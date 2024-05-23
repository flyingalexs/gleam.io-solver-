
import tls_client
import random
import string
import requests
import time
import re
import coloredlogs
import logging
api_url2 = 'https://api.capmonster.cloud/'
key = 'your cmonster key'
coloredlogs.install(level="INFO")
logger = logging.getLogger(__name__)
def create_task_capmonster(task_payload):
    return requests.post(api_url2 + "createTask", json=task_payload).json()
def get_balance():
    return requests.post(api_url2+ "getBalance", json={'clientKey': key}).json()['balance']


# Function to get CAPMonster task result
def get_task_result_capmonster(task_id):
    payload = {"clientKey": key, "taskId": task_id}
    return requests.post(api_url2 + "getTaskResult", json=payload).json()
def solve():
    payload = {
        "clientKey": key,
        "task": {
            "type": "TurnstileTaskProxyless",
            "websiteURL": "https://gleam.io/enter/kFm1d/7651539",
            "websiteKey": "0x4AAAAAAAAma6FCjIY5lVkD"
        }
    }
    res = create_task_capmonster(payload)
    task_id = res.get('taskId')
    while True:
        time.sleep(1)
        res = get_task_result_capmonster(task_id)
        status = res.get("status")
        if status == "ready":
            logger.info(f"Got captcha token.. {res['solution']['token'][:12]}...")
            return res['solution']['token']
        else:
            logger.info(res)
            continue
