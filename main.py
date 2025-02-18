import json
import logging
import os
import time
import argparse
import warnings
from typing import Tuple, Dict, Any
from threading import Thread
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

# Global Variables
TL_URL = os.environ.get("TL_URL")
RATE_LIMIT = 30  # requests
RATE_LIMIT_PERIOD = 31  # seconds
WORKER_THREADS = 6  # Number of worker threads for processing

request_queue = Queue()
output_queue = Queue()


def configure_logging(debug: bool):
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug logging is enabled.")
        logging.captureWarnings(True)
        urllib3_logger = logging.getLogger("urllib3")
        urllib3_logger.setLevel(logging.DEBUG)
    else:
        urllib3_logger = logging.getLogger("urllib3")
        urllib3_logger.setLevel(
            logging.ERROR
        )  # Suppress urllib3 warnings when not in debug mode
        warnings.filterwarnings(
            "ignore", category=urllib3.exceptions.InsecureRequestWarning
        )


def producer(token: str, limit: int):
    if TL_URL is None:
        logging.error("TL_URL environment variable is missing")
        return

    offset = 0
    request_count = 0
    start_time = time.time()

    while True:
        # Implement rate limiting
        if request_count >= RATE_LIMIT:
            elapsed_time = time.time() - start_time
            if elapsed_time < RATE_LIMIT_PERIOD:
                sleep_time = RATE_LIMIT_PERIOD - elapsed_time
                logging.info(
                    f"Rate limit reached. Sleeping for {sleep_time} seconds..."
                )
                time.sleep(sleep_time)
            request_count = 0
            start_time = time.time()

        status_code, response_text = get_containers(token, offset, limit)
        request_count += 1

        if status_code != 200:
            logging.error(f"Error fetching containers: {status_code}")
            break

        containers = json.loads(response_text)
        if not containers:
            break  # No more data to fetch

        for container in containers:
            request_queue.put(container)

        if len(containers) < limit:
            break  # Last page has fewer items, we're done

        offset += limit

    # Indicate that no more data will be sent
    for _ in range(WORKER_THREADS):
        request_queue.put(None)


def consumer():
    while True:
        container = request_queue.get()
        if container is None:
            break

        container_info = extract_network_info(container)
        if container_info:
            output_queue.put(container_info)

        request_queue.task_done()

    # Indicate that no more data will be processed
    output_queue.put(None)


def outputter():
    while True:
        container_info = output_queue.get()
        if container_info is None:
            break
        print(json.dumps(container_info, indent=2))  # Use print for output
        output_queue.task_done()


def get_containers(token: str, offset: int = 0, limit: int = 100) -> Tuple[int, str]:
    containers_url = TL_URL + "/api/v1/containers"

    headers = {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
    }

    params = {"offset": offset, "limit": limit}

    response = requests.get(
        containers_url, headers=headers, params=params, timeout=60, verify=False
    )
    if response.status_code == 401:
        time.sleep(100)
        print("recieved 401, sleeping for 1 second and then re-trying")
        response = requests.get(
            containers_url, headers=headers, params=params, timeout=60, verify=False
        )
    return response.status_code, response.text


def extract_network_info(container: Dict[str, Any]) -> Dict[str, Any]:
    container_id = container.get("_id")

    open_ports = []

    # Extract ports from `network` object
    network = container.get("network", {})
    network_ports = network.get("ports", [])
    for port in network_ports:
        open_ports.append(
            {
                "port": port.get("container"),
                "host_port": port.get("host"),
                "host_ip": port.get("hostIP"),
                "nat": port.get("nat"),
                "type": "network",
            }
        )

    # Extract ports from `networkSettings` object
    network_settings = container.get("networkSettings", {})
    settings_ports = network_settings.get("ports", [])
    for port in settings_ports:
        open_ports.append(
            {
                "port": port.get("containerPort"),
                "host_port": port.get("hostPort"),
                "host_ip": port.get("hostIP"),
                "type": "networkSettings",
            }
        )

    # Extract ports from `firewallProtection` object
    firewall_protection = container.get("firewallProtection", {})
    fw_ports = firewall_protection.get("ports", [])
    for port in fw_ports:
        open_ports.append({"port": port, "type": "firewallProtection"})
    tls_ports = firewall_protection.get("tlsPorts", [])
    for port in tls_ports:
        open_ports.append({"port": port, "type": "firewallProtection_tls"})
    unprotected_processes = firewall_protection.get("unprotectedProcesses", [])
    for process in unprotected_processes:
        open_ports.append(
            {
                "port": process.get("port"),
                "process": process.get("process"),
                "tls": process.get("tls"),
                "type": "unprotectedProcess",
            }
        )

    if open_ports:
        container_info = {
            "id": container_id,
            "open_ports": open_ports,
            "network": network,
            "networks": network_settings,
        }
        return container_info

    return {}


def generate_cwp_token(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    if TL_URL is None:
        logging.error("TL_URL environment variable is missing")
        exit(1)

    auth_url = f"{TL_URL}/api/v1/authenticate"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        auth_url, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.warning(
            f"Unable to acquire token with error code: {response.status_code}"
        )
        return response.status_code, ""


def check_param(param_name: str) -> str:
    param_value = os.environ.get(param_name)
    if param_value is None:
        logging.error(f"Missing {param_name}")
        raise ValueError(f"Missing {param_name}")
    return param_value


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Fetch and display container network information. Use --debug to show debug messages."
    )
    parser.add_argument("--debug", action="store_true", help="Show debug messages.")
    args = parser.parse_args()

    configure_logging(args.debug)

    P: Tuple[str, str, str] = ("PC_IDENTITY", "PC_SECRET", "TL_URL")
    accessKey, accessSecret, _ = map(check_param, P)
    response_code, cwp_token = (
        generate_cwp_token(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )

    if not cwp_token:
        logging.error("Token generation failed")
        exit(1)

    # Start the producer thread
    producer_thread = Thread(target=producer, args=(cwp_token, 100))
    producer_thread.start()

    # Start the output thread
    output_thread = Thread(target=outputter)
    output_thread.start()

    # Start the worker threads
    worker_threads = []
    for _ in range(WORKER_THREADS):
        worker_thread = Thread(target=consumer)
        worker_threads.append(worker_thread)
        worker_thread.start()

    # Wait for the producer thread to complete
    producer_thread.join()

    # Wait for the worker threads to complete
    for worker_thread in worker_threads:
        worker_thread.join()

    # Indicate to the output thread that processing is complete
    output_queue.put(None)

    # Wait for the output thread to complete
    output_thread.join()


if __name__ == "__main__":
    main()
