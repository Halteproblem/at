import requests
import random
import json
import re
import time
import hashlib
import urllib.parse
import sys
import logging
from base64 import urlsafe_b64decode
from pathlib import Path


# Setup logging
def setup_logging():
    """Configure logging to both file and console"""
    # Create logs directory if it doesn't exist
    Path("logs").mkdir(exist_ok=True)

    # Create formatters
    file_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)-12s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S"
    )

    # Create file handler with rotation
    from logging.handlers import RotatingFileHandler

    file_handler = RotatingFileHandler(
        "logs/service.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # Reduce noise from requests library
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)


# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Global base64-encoded URLs - decoded once at startup
_ENCODED_URLS = {
    "BASE_URL": b"aHR0cHM6Ly93d3cuYWxkaXRhbGsta3VuZGVucG9ydGFsLmRlLw==",
    "AUTH_URL": b"aHR0cHM6Ly9sb2dpbi5hbGRpdGFsay1rdW5kZW5iZXRyZXV1bmcuZGUvc2lnbmluL2pzb24vcmVhbG1zL3Jvb3QvcmVhbG1zL2FsZGl0YWxrL2F1dGhlbnRpY2F0ZT9nb3RvPXt9JnNlcnZpY2U9TG9naW4mbG9jYWxlPWRlJmF1dGhJbmRleFR5cGU9c2VydmljZSZhdXRoSW5kZXhWYWx1ZT1Mb2dpbg==",
    "DASHBOARD_URL": b"aHR0cHM6Ly93d3cuYWxkaXRhbGsta3VuZGVucG9ydGFsLmRlL3Njcy9iZmYvc2NzLTIwOS1zZWxmY2FyZS1kYXNoYm9hcmQtYmZmL3NlbGZjYXJlLWRhc2hib2FyZC92MS9vZmZlcnMve30/d2FybmluZ0RheXM9MjgmY29udHJhY3RJZD17fSZwcm9kdWN0VHlwZT1Nb2JpbGVfUHJvZHVjdF9PZmZlcg==",
    "UPDATE_URL": b"aHR0cHM6Ly93d3cuYWxkaXRhbGsta3VuZGVucG9ydGFsLmRlL3Njcy9iZmYvc2NzLTIwOS1zZWxmY2FyZS1kYXNoYm9hcmQtYmZmL3NlbGZjYXJlLWRhc2hib2FyZC92MS9vZmZlci91cGRhdGVVbmxpbWl0ZWQ=",
    "USER_URL": b"aHR0cHM6Ly9sb2dpbi5hbGRpdGFsay1rdW5kZW5iZXRyZXV1bmcuZGUvc2lnbmluL2pzb24vcmVhbG1zL3Jvb3QvcmVhbG1zL2FsZGl0YWxrL3VzZXJzL3t9",
    "NAVIGATION_URL": b"aHR0cHM6Ly93d3cuYWxkaXRhbGsta3VuZGVucG9ydGFsLmRlL3Njcy9iZmYvc2NzLTIwNy1jdXN0b21lci1tYXN0ZXItZGF0YS1iZmYvY3VzdG9tZXItbWFzdGVyLWRhdGEvdjEvbmF2aWdhdGlvbi1saXN0P21zaXNkbj17fQ==",
}

# Decode all URLs once at module load time
URLS = {
    key: urlsafe_b64decode(value).decode("utf-8")
    for key, value in _ENCODED_URLS.items()
}


class POW:
    def __init__(self):
        self.uuid = None
        self.difficulty = None
        self.nonce = None
        self.digest = None
        self.logger = logging.getLogger(f"{__name__}.POW")

    def solve_pow(self):
        """Solve proof-of-work: find nonce such that SHA1(uuid + nonce) starts with `difficulty` zeros."""
        target = "0" * self.difficulty
        nonce = 0
        self.logger.info(
            f"Solving PoW: finding nonce so SHA1({self.uuid} + nonce) starts with '{target}'..."
        )
        start_time = time.time()

        while True:
            msg = f"{self.uuid}{nonce}".encode("utf-8")
            digest = hashlib.sha1(msg).hexdigest()
            if digest.startswith(target):
                elapsed = time.time() - start_time
                self.logger.info(
                    f"Found nonce: {nonce}, hash: {digest} (took {elapsed:.2f}s)"
                )
                self.nonce = nonce
                self.digest = digest
                return nonce
            nonce += 1
            if nonce % 100000 == 0:
                elapsed = time.time() - start_time
                self.logger.debug(f"Tested {nonce} nonces... ({elapsed:.2f}s elapsed)")

    def extract_pow_params(self, response_json):
        """Extract difficulty and uuid (work) from TextOutputCallback JS."""
        js_code = ""
        for cb in response_json.get("callbacks", []):
            if cb.get("type") == "TextOutputCallback":
                for out in cb.get("output", []):
                    if out.get("name") == "message":
                        js_code = out.get("value", "")
                        break

        difficulty_match = re.search(r"var difficulty = (\d+);", js_code)
        work_match = re.search(r'var work = "([^"]+)";', js_code)

        if not difficulty_match or not work_match:
            raise ValueError("Could not extract PoW parameters from response")

        difficulty = int(difficulty_match.group(1))
        work = work_match.group(1)

        self.uuid = work
        self.difficulty = difficulty
        self.logger.debug(f"Found difficulty: {difficulty}, work: {work}")


class ServiceException(Exception):
    """Custom exception for service operations"""

    pass


class AT:
    headers_json = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    headers_html = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AT")
        self.session = requests.Session()
        self.pow = POW()
        self.username, self.password, self.delay = self._load_config()

        # User data
        self.customer_id = None
        self.contract_id = None

        # Subscription data
        self.offer_id = None
        self.subscription_id = None
        self.refill_threshold_value_uid = None
        self.on_demand_amount_value_uid = None
        self.resource_id = None

        self.logger.info("Service initialized")

    def _handle_request(self, operation, request_func, *args, **kwargs):
        """Safe request handler with proper error handling"""
        try:
            self.logger.debug(
                f"{operation}: Making request to {args[0] if args else 'unknown URL'}"
            )
            response = request_func(*args, **kwargs)

            # Log request details
            self.logger.info(f"{operation}: HTTP {response.status_code}")
            if response.status_code >= 400:
                self.logger.error(
                    f"{operation}: Response body: {response.text[:500]}..."
                )

            if response.status_code == 401:
                raise ServiceException("Session expired - login required")
            elif response.status_code >= 400:
                raise ServiceException(f"HTTP {response.status_code}: {response.text}")

            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"{operation}: Network error: {str(e)}")
            raise ServiceException(f"Network error during {operation}: {str(e)}")
        except json.JSONDecodeError as e:
            self.logger.error(f"{operation}: JSON decode error: {str(e)}")
            raise ServiceException(
                f"Invalid JSON response during {operation}: {str(e)}"
            )

    def get_login_payload(self, auth_id, initial_data, callbacks, nonce):
        payload = {
            "authId": auth_id,
            "stage": initial_data["stage"],
            "header": initial_data["header"],
            "callbacks": [],
        }

        for cb in callbacks:
            new_cb = cb.copy()
            cb_type = cb["type"]

            if cb_type == "HiddenValueCallback":
                name = cb["input"][0]["name"]
                if name == "IDToken1":  # PoW nonce
                    new_cb["input"][0]["value"] = str(nonce)
                elif name == "IDToken6":  # Remember me
                    new_cb["input"][0]["value"] = "checked"
            elif cb_type == "NameCallback":
                new_cb["input"][0]["value"] = self.username
            elif cb_type == "PasswordCallback":
                new_cb["input"][0]["value"] = "***"  # Don't log actual password
            elif cb_type == "ConfirmationCallback":
                new_cb["input"][0]["value"] = "2"  # Login button

            payload["callbacks"].append(new_cb)

        # Set actual password after logging
        for cb in payload["callbacks"]:
            if cb["type"] == "PasswordCallback":
                cb["input"][0]["value"] = self.password

        return payload

    def update_status(self):
        """Update subscription status with safe error handling"""
        try:
            if not all(
                [
                    self.offer_id,
                    self.subscription_id,
                    self.refill_threshold_value_uid,
                    self.on_demand_amount_value_uid,
                    self.resource_id,
                ]
            ):
                raise ServiceException(
                    "Missing subscription data - call get_status() first"
                )

            self.logger.info(
                f"Attempting to update status for subscription {self.subscription_id}"
            )
            response = self._handle_request(
                "UPDATE_STATUS",
                self.session.post,
                URLS["UPDATE_URL"],
                headers=self.headers_json,
                json={
                    "offerId": self.offer_id,
                    "subscriptionId": self.subscription_id,
                    "refillThresholdValue": self.refill_threshold_value_uid,
                    "amount": self.on_demand_amount_value_uid,
                    "updateOfferResourceID": self.resource_id,
                },
            )

            data = response.json()
            message = data.get("message", "No message")
            is_updated = data.get("isUpdated", False)

            if is_updated:
                self.logger.info(f"Status update successful: {message}")
            else:
                self.logger.warning(f"Status update failed: {message}")

            return is_updated

        except ServiceException as e:
            self.logger.error(f"Update status failed: {e}")
            return False

    def get_status(self):
        """Get subscription status with safe error handling"""
        try:
            if not self.customer_id or not self.contract_id:
                raise ServiceException("Missing customer/contract ID - login required")

            self.logger.debug(
                f"Getting status for customer {self.customer_id}, contract {self.contract_id}"
            )
            response = self._handle_request(
                "GET_STATUS",
                self.session.get,
                URLS["DASHBOARD_URL"].format(self.customer_id, self.contract_id),
                headers=self.headers_json,
            )

            data = response.json()

            if not data.get("subscribedOffers"):
                self.logger.warning("No subscriptions available")
                return None

            for subscription in data["subscribedOffers"]:
                offer_name = subscription.get("offerName", "n/a")

                if not subscription.get("refillThresholdValue"):
                    self.logger.info(f"Subscription {offer_name} does not allow refill")
                    continue

                # Store subscription data
                self.offer_id = subscription.get("offerId")
                self.subscription_id = subscription.get("subscriptionId")
                self.refill_threshold_value_uid = subscription.get(
                    "refillThresholdValueUid"
                )
                self.on_demand_amount_value_uid = subscription.get(
                    "onDemandAmountValueUid"
                )
                self.resource_id = subscription.get("resourceId")

                refill_threshold = (
                    int(subscription.get("refillThresholdValue").split(" ")[0]) << 20
                )

                for pack in subscription.get("pack", []):
                    if pack.get("balanceAttributeReference") == "dataGrantAmount":
                        allocated = int(pack.get("allocated", 0))
                        used = int(pack.get("used", 0))
                        left = allocated - used

                        unit = "GiB" if left >= 1048576 else "MiB"
                        amount = left >> 20 if left >= 1048576 else left >> 10

                        can_refill = left < refill_threshold
                        threshold_display = (
                            refill_threshold >> 20
                            if refill_threshold >= 1048576
                            else refill_threshold >> 10
                        )
                        threshold_unit = "GiB" if refill_threshold >= 1048576 else "MiB"

                        self.logger.info(f"Data status - Subscription: {offer_name}")
                        self.logger.info(f"Data remaining: {amount} {unit}")
                        self.logger.info(
                            f"Refill threshold: {threshold_display} {threshold_unit}"
                        )
                        self.logger.info(f"Can refill: {'Yes' if can_refill else 'No'}")

                        return can_refill

            self.logger.warning("No data packs found in subscriptions")
            return False

        except ServiceException as e:
            self.logger.error(f"Get status failed: {e}")
            return None

    def login(self):
        """Login with safe error handling"""
        try:
            self.logger.info("Starting login process")
            start_time = time.time()

            # Initial request
            response = self._handle_request(
                "LOGIN_INIT",
                self.session.get,
                URLS["BASE_URL"],
                headers=self.headers_html,
            )

            parsed = urllib.parse.urlparse(response.url)
            query = urllib.parse.parse_qs(parsed.query)
            goto_url = query["goto"][0]
            self.logger.debug(f"Got redirect URL: {goto_url}")

            # Auth request
            auth_url = URLS["AUTH_URL"].format(urllib.parse.quote(goto_url))
            response = self._handle_request(
                "LOGIN_AUTH", self.session.post, auth_url, headers=self.headers_json
            )

            initial_data = response.json()
            auth_id = initial_data["authId"]
            callbacks = initial_data["callbacks"]
            self.logger.debug(f"Got auth ID: {auth_id}")

            # Solve PoW
            self.pow.extract_pow_params(initial_data)
            nonce = self.pow.solve_pow()
            payload = self.get_login_payload(auth_id, initial_data, callbacks, nonce)

            # Submit login
            response = self._handle_request(
                "LOGIN_SUBMIT",
                self.session.post,
                auth_url,
                json=payload,
                headers=self.headers_json,
            )

            success_url = response.json().get("successUrl")
            if not success_url:
                raise ServiceException("Login failed - no success URL received")

            self.logger.debug(f"Got success URL: {success_url}")

            # Follow success URL
            response = self._handle_request(
                "LOGIN_SUCCESS",
                self.session.get,
                success_url,
                headers=self.headers_html,
            )

            # Get user data if not already available
            if not self.customer_id or not self.contract_id:
                self._fetch_user_data()

            elapsed = time.time() - start_time
            self.logger.info(f"Login successful (took {elapsed:.2f}s)")
            return True

        except ServiceException as e:
            self.logger.error(f"Login failed: {e}")
            return False

    def _fetch_user_data(self):
        """Fetch customer and contract IDs"""
        self.logger.debug("Fetching user data")

        self.customer_id = self.session.cookies.get("tef_customer_id")
        user_id = self.session.cookies.get("user_id")

        if not user_id:
            raise ServiceException("User ID not found in cookies")

        self.logger.debug(f"Customer ID: {self.customer_id}, User ID: {user_id}")

        # Get user details
        response = self._handle_request(
            "FETCH_USER",
            self.session.get,
            URLS["USER_URL"].format(user_id),
            headers=self.headers_json,
        )

        msidn = response.json().get("telephoneNumber", [None])[0]
        if not msidn:
            raise ServiceException("Phone number not found")

        self.logger.debug(f"Phone number: {msidn}")

        # Get contract details
        response = self._handle_request(
            "FETCH_CONTRACT",
            self.session.get,
            URLS["NAVIGATION_URL"].format(msidn),
            headers=self.headers_json,
        )

        contracts_found = 0
        for subscription in (
            response.json().get("userDetails", {}).get("subscriptions", [])
        ):
            contracts_found += 1
            if (
                subscription.get("portfolioStatus") == "active"
                and subscription.get("productOfferType") == "Mobile_Product_Offer"
            ):
                self.contract_id = subscription.get("contractId")
                self.logger.debug(f"Found active contract: {self.contract_id}")
                break

        self.logger.debug(f"Checked {contracts_found} contracts")

        if not self.contract_id:
            raise ServiceException("No active mobile contract found")

    @staticmethod
    def _load_config():
        try:
            with open("config.json", "r") as f:
                data = json.load(f)
            return data["username"], data["password"], data["delay"]
        except (FileNotFoundError, KeyError) as e:
            raise ServiceException(f"Config error: {e}")


def main():
    """Main loop with safe error handling"""
    logger.info("=== Service starting ===")
    service = AT()

    # Initial login
    if not service.login():
        logger.error("Initial login failed - exiting")
        return

    check_count = 0
    refill_count = 0
    login_count = 0

    while True:
        try:
            check_count += 1
            logger.info(f"=== Status check #{check_count} ===")

            status = service.get_status()

            if status is None:
                logger.warning("Could not get status, retrying in 60 seconds...")
                time.sleep(60)
                continue
            elif status:
                logger.info("Refill needed - attempting to update status...")
                if service.update_status():
                    refill_count += 1
                    logger.info(
                        f"✅ Status updated successfully (total refills: {refill_count})"
                    )
                else:
                    logger.error("❌ Status update failed")
            else:
                logger.info("No refill needed")

            # Wait before next check
            delay = random.uniform(service.delay*0.8, service.delay*1.2)
            logger.info(f"Waiting {delay} seconds until next check...")
            time.sleep(delay)

        except ServiceException as e:
            if "Session expired" in str(e):
                if login_count > 10:
                    logger.error(f"Re-login failed {login_count} times, exiting...")
                    sys.exit()
                logger.warning("Session expired, attempting to re-login...")
                if not service.login():
                    logger.error("Re-login failed, waiting 30 seconds...")
                    time.sleep(30)
                else:
                    login_count = 0
            else:
                logger.error(f"Error in main loop: {e}")
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal - exiting gracefully...")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}", exc_info=True)
            time.sleep(60)

    logger.info(
        f"=== Service stopped - Total checks: {check_count}, Total refills: {refill_count} ==="
    )


if __name__ == "__main__":
    main()
