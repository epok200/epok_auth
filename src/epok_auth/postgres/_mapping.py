from typing import Any

from sqlalchemy.engine import RowMapping

from epok_auth.google.models import (
    ExternalIdentity,
    GoogleChallenge,
    GoogleChallengePurpose,
)
from epok_auth.models import RefreshSession, UserAccount, UserStatus
from epok_auth.passkeys.models import (
    PasskeyCeremonyPurpose,
    PasskeyChallenge,
    PasskeyCredential,
)

type SqlValues = dict[str, Any]


def user_values(user: UserAccount) -> SqlValues:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "password_hash": user.password_hash,
        "status": user.status.value,
        "roles": list(user.roles),
        "scopes": list(user.scopes),
        "must_change_password": user.must_change_password,
        "password_login_enabled": user.password_login_enabled,
        "google_auto_link_allowed": user.google_auto_link_allowed,
        "failed_login_attempts": user.failed_login_attempts,
        "locked_until": user.locked_until,
        "password_changed_at": user.password_changed_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def session_values(session: RefreshSession) -> SqlValues:
    return {
        "id": session.id,
        "user_id": session.user_id,
        "family_id": session.family_id,
        "token_hash": session.token_hash,
        "csrf_hash": session.csrf_hash,
        "created_at": session.created_at,
        "idle_expires_at": session.idle_expires_at,
        "absolute_expires_at": session.absolute_expires_at,
        "authenticated_at": session.authenticated_at,
        "used_at": session.used_at,
        "revoked_at": session.revoked_at,
        "replaced_by_id": session.replaced_by_id,
    }


def passkey_values(credential: PasskeyCredential) -> SqlValues:
    return {
        "id": credential.id,
        "user_id": credential.user_id,
        "credential_id": credential.credential_id,
        "public_key": credential.public_key,
        "name": credential.name,
        "sign_count": credential.sign_count,
        "aaguid": credential.aaguid,
        "transports": list(credential.transports),
        "device_type": credential.device_type,
        "backed_up": credential.backed_up,
        "created_at": credential.created_at,
        "last_used_at": credential.last_used_at,
        "revoked_at": credential.revoked_at,
    }


def challenge_values(challenge: PasskeyChallenge) -> SqlValues:
    return {
        "id": challenge.id,
        "purpose": challenge.purpose.value,
        "challenge": challenge.challenge,
        "origin": challenge.origin,
        "user_id": challenge.user_id,
        "created_at": challenge.created_at,
        "expires_at": challenge.expires_at,
        "consumed_at": challenge.consumed_at,
    }


def google_challenge_values(challenge: GoogleChallenge) -> SqlValues:
    return {
        "id": challenge.id,
        "purpose": challenge.purpose.value,
        "nonce": challenge.nonce,
        "origin": challenge.origin,
        "client_id": challenge.client_id,
        "user_id": challenge.user_id,
        "created_at": challenge.created_at,
        "expires_at": challenge.expires_at,
        "consumed_at": challenge.consumed_at,
    }


def external_identity_values(identity: ExternalIdentity) -> SqlValues:
    return {
        "id": identity.id,
        "user_id": identity.user_id,
        "issuer": identity.issuer,
        "subject": identity.subject,
        "email": identity.email,
        "created_at": identity.created_at,
        "last_login_at": identity.last_login_at,
    }


def user_from_row(row: RowMapping) -> UserAccount:
    return UserAccount(
        id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        password_hash=row["password_hash"],
        status=UserStatus(row["status"]),
        roles=tuple(row["roles"] or ()),
        scopes=tuple(row["scopes"] or ()),
        must_change_password=row["must_change_password"],
        password_login_enabled=row["password_login_enabled"],
        google_auto_link_allowed=row["google_auto_link_allowed"],
        failed_login_attempts=row["failed_login_attempts"],
        locked_until=row["locked_until"],
        password_changed_at=row["password_changed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def session_from_row(row: RowMapping) -> RefreshSession:
    return RefreshSession(
        id=row["id"],
        user_id=row["user_id"],
        family_id=row["family_id"],
        token_hash=row["token_hash"],
        csrf_hash=row["csrf_hash"],
        created_at=row["created_at"],
        idle_expires_at=row["idle_expires_at"],
        absolute_expires_at=row["absolute_expires_at"],
        authenticated_at=row["authenticated_at"],
        used_at=row["used_at"],
        revoked_at=row["revoked_at"],
        replaced_by_id=row["replaced_by_id"],
    )


def passkey_from_row(row: RowMapping) -> PasskeyCredential:
    return PasskeyCredential(
        id=row["id"],
        user_id=row["user_id"],
        credential_id=bytes(row["credential_id"]),
        public_key=bytes(row["public_key"]),
        name=row["name"],
        sign_count=row["sign_count"],
        aaguid=row["aaguid"],
        transports=tuple(row["transports"] or ()),
        device_type=row["device_type"],
        backed_up=row["backed_up"],
        created_at=row["created_at"],
        last_used_at=row["last_used_at"],
        revoked_at=row["revoked_at"],
    )


def challenge_from_row(row: RowMapping) -> PasskeyChallenge:
    return PasskeyChallenge(
        id=row["id"],
        purpose=PasskeyCeremonyPurpose(row["purpose"]),
        challenge=bytes(row["challenge"]),
        origin=row["origin"],
        user_id=row["user_id"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def google_challenge_from_row(row: RowMapping) -> GoogleChallenge:
    return GoogleChallenge(
        id=row["id"],
        purpose=GoogleChallengePurpose(row["purpose"]),
        nonce=row["nonce"],
        origin=row["origin"],
        client_id=row["client_id"],
        user_id=row["user_id"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        consumed_at=row["consumed_at"],
    )


def external_identity_from_row(row: RowMapping) -> ExternalIdentity:
    return ExternalIdentity(
        id=row["id"],
        user_id=row["user_id"],
        issuer=row["issuer"],
        subject=row["subject"],
        email=row["email"],
        created_at=row["created_at"],
        last_login_at=row["last_login_at"],
    )
