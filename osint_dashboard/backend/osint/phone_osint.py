"""
Phone Number OSINT
------------------
Given a phone number (ideally in international format, e.g. +49...),
determine its country of origin, region, the mobile carrier
(Mobilfunk-Anbieter), line type and validity.

Uses Google's libphonenumber (via the `phonenumbers` package), which
ships an offline database of carrier and geocoding metadata, so no
external API keys are required.
"""
from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, timezone


LINE_TYPES = {
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "Shared cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    phonenumbers.PhoneNumberType.PAGER: "Pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}

# ISO country code -> flag emoji, purely cosmetic for the UI.
def _flag(region_code: str) -> str:
    if not region_code or len(region_code) != 2:
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in region_code.upper())


def analyze_phone(raw_number: str, default_region: str | None = None) -> dict:
    raw_number = (raw_number or "").strip()
    if not raw_number:
        return {"ok": False, "error": "No phone number provided."}

    # If the user didn't type a leading +, try to parse it with a hint region.
    # We attempt international first, then fall back to the default region.
    parsed = None
    parse_error = None
    attempts = []
    if raw_number.startswith("+") or raw_number.startswith("00"):
        attempts.append(None)
    if default_region:
        attempts.append(default_region)
    attempts.append(None)
    attempts.append("US")

    for region in attempts:
        try:
            candidate = phonenumbers.parse(raw_number, region)
            if phonenumbers.is_possible_number(candidate):
                parsed = candidate
                break
            parsed = parsed or candidate
        except phonenumbers.NumberParseException as exc:  # pragma: no cover
            parse_error = str(exc)
            continue

    if parsed is None:
        return {
            "ok": False,
            "error": f"Could not parse number. {parse_error or 'Try international format, e.g. +49 151 12345678.'}",
        }

    is_valid = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    region_code = phonenumbers.region_code_for_number(parsed) or ""
    number_type = phonenumbers.number_type(parsed)

    carrier_name = carrier.name_for_number(parsed, "en") or ""
    location = geocoder.description_for_number(parsed, "en") or ""
    tzs = list(timezone.time_zones_for_number(parsed))

    country_name = ""
    if region_code:
        try:
            import pycountry  # optional
            c = pycountry.countries.get(alpha_2=region_code)
            country_name = c.name if c else ""
        except Exception:
            country_name = ""

    return {
        "ok": True,
        "input": raw_number,
        "valid": is_valid,
        "possible": is_possible,
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "country_code": parsed.country_code,
        "region_code": region_code,
        "country_name": country_name or location,
        "flag": _flag(region_code),
        "location": location,
        "carrier": carrier_name or "Unknown / not portable-tracked",
        "line_type": LINE_TYPES.get(number_type, "Unknown"),
        "timezones": tzs,
    }
