# SPDX-FileCopyrightText: 2026 Marcin Zieba <marcinpsk@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# Test fixtures for kea-ownership-read-without-database-error. Intentionally
# contains rule-violating code; excluded from ruff (see pyproject exclude).


def bad_advisory(server, family, address, user):
    # ruleid: kea-ownership-read-without-database-error
    (found,) = address_ownership(server, family, "reservation", [address], user).values()
    return found


def bad_other_handler(server, family, addresses, user):
    try:
        # ruleid: kea-ownership-read-without-database-error
        return address_ownership(server, family, "reservation", addresses, user)
    except ValueError:
        return None


def good_badges(server, family, addresses, user):
    try:
        # ok: kea-ownership-read-without-database-error
        ownership = address_ownership(server, family, "reservation", addresses, user)
    except DatabaseError:
        logger.exception("Could not read NetBox IPAM state for Reservation badges")
        ownership = None
    return ownership


def good_tuple_and_other_handlers(server, family, addresses, user):
    try:
        # ok: kea-ownership-read-without-database-error
        return address_ownership(server, family, "reservation", addresses, user)
    except KeyError:
        return {}
    except (ValueError, DatabaseError):
        return None
