import logging
import os
from enum import Enum

import requests
from db import addons_db

MARKETPLACE_ADDR = os.environ.get("MARKETPLACE_ADDR") or "http://localhost:11102"
MARKETPLACE_API = f"{MARKETPLACE_ADDR}/api/v1/marketplace/addons"

addons_service = None


# TODO(ME): reuse this enum in addons_monitor
class AddonStatusEnum(Enum):
    INSTALLING = "installing"
    DISABLING = "disabling"

    DISABLED = "disabled"
    FAILED = "failed"
    ACTIVE = "active"
    PARTIALLY_ACTIVE = "partially_active"

    def __str__(self):
        return self.value


def get_addon_in_marketplace(marketplace_id, check_is_verified=True):
    response = requests.get(f"{MARKETPLACE_API}/{marketplace_id}")
    response.raise_for_status()

    marketplace_addon = response.json()
    if check_is_verified and marketplace_addon.get("status") != "approved":
        return None

    return marketplace_addon


def install_addon(addon):
    marketplace_id = addon.get("marketplace_id")
    marketplace_addon = get_addon_in_marketplace(marketplace_id, check_is_verified=False)

    if marketplace_addon is None:
        return None

    services = marketplace_addon.get("services", [])

    if not services:
        logging.error(f"Addon-{marketplace_id} has no services")
        return None

    addon["services"] = services
    addon["volumes"] = marketplace_addon.get("volumes", [])
    addon["networks"] = marketplace_addon.get("networks", [])
    addon["status"] = str(AddonStatusEnum.INSTALLING)

    created_addon = addons_db.create_addon(addon)

    return created_addon
