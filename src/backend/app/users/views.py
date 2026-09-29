from django.conf import settings

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
)

from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    UserSerializer,
)


def set_auth_cookies(response, refresh_token, access_token):
    response.set_cookie(
        key="access_token",
        value=str(access_token),
        httponly=True,
        secure=not settings.DEBUG,
        samesite="Lax",
        max_age=15 * 60,
    )

    response.set_cookie(
        key="refresh_token",
        value=str(refresh_token),
        httponly=True,
        secure=not settings.DEBUG,
        samesite="Lax",
        max_age=7 * 24 * 60 * 60,
    )


class RegisterView(APIView):

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Authentication"],
        summary="Register a new customer",
        description=(
            "Create a new customer account and authenticate the user "
            "using secure HttpOnly cookies."
        ),
        request=RegisterSerializer,
        responses={
            201: OpenApiResponse(
                response=UserSerializer,
                description="Registration successful.",
            ),
            400: OpenApiResponse(
                description="Invalid registration data.",
            ),
        },
    )
    def post(self, request):
        serializer = RegisterSerializer(
            data=request.data,
        )

        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response(
            {
                "message": "Registration successful.",
                "user": UserSerializer(user).data,
            },
            status=status.HTTP_201_CREATED,
        )

        set_auth_cookies(
            response,
            refresh,
            access,
        )

        return response


class LoginView(APIView):

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Authentication"],
        summary="Login",
        description=(
            "Authenticate a user using email and password. "
            "Access and refresh tokens are returned as secure "
            "HttpOnly cookies."
        ),
        request=LoginSerializer,
        responses={
            200: OpenApiResponse(
                response=UserSerializer,
                description="Login successful.",
            ),
            400: OpenApiResponse(
                description="Invalid credentials or request data.",
            ),
            401: OpenApiResponse(
                description="Authentication failed.",
            ),
        },
    )
    def post(self, request):
        serializer = LoginSerializer(
            data=request.data,
            context={"request": request},
        )

        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        refresh = RefreshToken.for_user(user)
        access = refresh.access_token

        response = Response(
            {
                "message": "Login successful.",
                "user": UserSerializer(user).data,
            }
        )

        set_auth_cookies(
            response,
            refresh,
            access,
        )

        return response


class MeView(APIView):

    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["Authentication"],
        summary="Get current user",
        description="Return the currently authenticated user's profile.",
        responses={
            200: UserSerializer,
            401: OpenApiResponse(
                description="Authentication credentials were not provided or are invalid.",
            ),
        },
    )
    def get(self, request):
        return Response(
            UserSerializer(request.user).data
        )


class LogoutView(APIView):

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Authentication"],
        summary="Logout",
        description=(
            "Blacklist the refresh token and remove authentication "
            "cookies from the client."
        ),
        request=None,
        responses={
            200: OpenApiResponse(
                description="Logout successful.",
            ),
        },
    )
    def post(self, request):
        refresh_token = request.COOKIES.get(
            "refresh_token"
        )

        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except TokenError:
                pass

        response = Response(
            {
                "message": "Logout successful."
            }
        )

        response.delete_cookie(
            "access_token",
            samesite="Lax",
        )

        response.delete_cookie(
            "refresh_token",
            samesite="Lax",
        )

        return response


class RefreshView(APIView):

    permission_classes = [AllowAny]

    @extend_schema(
        tags=["Authentication"],
        summary="Refresh access token",
        description=(
            "Generate a new access token using the refresh token "
            "stored in the HttpOnly refresh_token cookie."
        ),
        request=None,
        responses={
            200: OpenApiResponse(
                description="Access token refreshed successfully.",
            ),
            401: OpenApiResponse(
                description="Refresh token is missing, invalid, or expired.",
            ),
        },
    )
    def post(self, request):
        refresh_token = request.COOKIES.get(
            "refresh_token"
        )

        if not refresh_token:
            return Response(
                {
                    "detail": "Refresh token not found."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            refresh = RefreshToken(refresh_token)

            access = refresh.access_token

            response = Response(
                {
                    "message": "Token refreshed."
                }
            )

            response.set_cookie(
                key="access_token",
                value=str(access),
                httponly=True,
                secure=not settings.DEBUG,
                samesite="Lax",
                max_age=15 * 60,
            )

            return response

        except TokenError:
            return Response(
                {
                    "detail": "Invalid or expired refresh token."
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )