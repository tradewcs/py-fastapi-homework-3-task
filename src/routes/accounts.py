from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_db, get_settings, get_jwt_auth_manager
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.passwords import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface
from config.settings import BaseAppSettings

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )

        hashed_password = hash_password(user_data.password)

        user = UserModel(
            email=user_data.email,
            hashed_password=hashed_password,
            is_active=False,
            group_id=cast(int, group.id),
        )

        db.add(user)
        await db.flush()

        token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(token)

        await db.commit()
        await db.refresh(user)

        return UserRegistrationResponseSchema(id=user.id, email=user.email)

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_record = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token,
        )
    )

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == data.email)
        )

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token_record = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == data.token,
            )
        )

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.hashed_password = hash_password(data.password)
        await db.delete(token_record)
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if not user or not verify_password(
        data.password, user.hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_manager.create_access_token(
            user_id=cast(int, user.id),
            settings=settings,
        )

        refresh_token = jwt_manager.create_refresh_token(
            user_id=cast(int, user.id),
            settings=settings,
        )

        token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            token=refresh_token,
        )

        db.add(token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token, settings)
        user_id = cast(int, payload["user_id"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    token_record = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = await db.scalar(
        select(UserModel).where(UserModel.id == user_id)
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        user_id=user_id,
        settings=settings,
    )

    return TokenRefreshResponseSchema(access_token=access_token)
