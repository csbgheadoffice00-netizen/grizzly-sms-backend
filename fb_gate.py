import logging

logger = logging.getLogger(__name__)

def check_facebook(country_id: int, mode="observe"):
    if country_id == 187:
        if mode == "observe":
            logger.warning(f"fb_gate would block country={country_id}")
        elif mode == "enforce":
            return False, "Facebook signups are blocked for this country."
    return True, ""
