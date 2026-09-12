import random
import sys
import time
import requests

BASE_URL = "http://127.0.0.1:5000"

random.seed(42)


def headers_for(ip, simulation_run):
    return {
        "X-Simulated-IP": ip,
        "X-Simulation-Run": simulation_run
    }


def send_home(ip, simulation_run):
    requests.get(
        f"{BASE_URL}/",
        headers=headers_for(ip, simulation_run),
        timeout=5
    )


def send_admin(ip, simulation_run):
    requests.get(
        f"{BASE_URL}/admin",
        headers=headers_for(ip, simulation_run),
        timeout=5
    )


def send_failed_login(ip, simulation_run, attempt):
    data = {
        "username": "admin",
        "password": f"wrong_password_{attempt}"
    }

    requests.post(
        f"{BASE_URL}/login",
        headers=headers_for(ip, simulation_run),
        data=data,
        timeout=5
    )


def generate_normal_users(ips, simulation_run):
    for ip in ips:
        number_of_requests = random.randint(5, 12)

        for _ in range(number_of_requests):
            action = random.choices(
                ["home", "admin"],
                weights=[0.75, 0.25],
                k=1
            )[0]

            if action == "home":
                send_home(ip, simulation_run)
            else:
                send_admin(ip, simulation_run)

            time.sleep(0.03)


def generate_baseline():
    simulation_run = "baseline_v1"

    normal_ips = [
        f"192.0.2.{i}"
        for i in range(10, 40)
    ]

    print("Generating BASELINE normal traffic...")

    generate_normal_users(
        normal_ips,
        simulation_run
    )

    print("baseline_v1 complete.")


def generate_evaluation():
    simulation_run = "evaluation_v1"

    normal_ips = [
        f"192.0.2.{i}"
        for i in range(50, 80)
    ]

    print("Generating EVALUATION normal traffic...")

    generate_normal_users(
        normal_ips,
        simulation_run
    )

    print("Generating brute-force behaviour...")

    for attempt in range(1, 21):
        send_failed_login(
            "203.0.113.50",
            simulation_run,
            attempt
        )
        time.sleep(0.03)

    print("Generating unusual admin-access volume...")

    for _ in range(25):
        send_admin(
            "203.0.113.51",
            simulation_run
        )
        time.sleep(0.03)

    print("Generating unusual request volume...")

    for _ in range(40):
        send_home(
            "203.0.113.52",
            simulation_run
        )
        time.sleep(0.03)

    print("evaluation_v1 complete.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("python generate_traffic.py baseline")
        print("python generate_traffic.py evaluation")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "baseline":
        generate_baseline()

    elif mode == "evaluation":
        generate_evaluation()

    else:
        print("Unknown mode. Use baseline or evaluation.")