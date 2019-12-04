import hashlib
import logging
import os

try:
    from django.urls import reverse
except ImportError:  # Will be removed in Django 2.0
    from django.core.urlresolvers import reverse

from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types.authorization_code import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.grant_types.refresh_token import RefreshTokenGrant

from social_django.views import NAMESPACE
from social_django.utils import load_backend, load_strategy
from social_core.exceptions import MissingBackend, SocialAuthBaseException
from social_core.utils import requests

from .settings import DRFSO2_URL_NAMESPACE


log = logging.getLogger(__name__)


class ConvertAuthorizationCodeGrant(RefreshTokenGrant):
    
    """This grant type validates an authorization code received from a third-party
    authentication backend, internally requests an access token from the backend
    and converts it to a social token.

    Uses `Refresh token grant`_ as the base.
    .. _`Refresh token grant`: http://tools.ietf.org/html/rfc6749#section-6
    """

    def validate_token_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        # This code is mostly based on AuthorizationCodeGrant.validate_token_request,
        # but modified to suit our needs. It omits authorization_code validation
        # and invalidation since we are passing it to social-auth-app-django to
        # handle access_token retrieval.

        # We are going to need to set these as None by default
        # to avoid AttributeError later
        request._params.setdefault('backend', None)
        request._params.setdefault('client_secret', None)

        if request.grant_type != 'convert_code':
            raise errors.UnsupportedGrantTypeError(request=request)

        # We check that a backend parameter is present.
        # It should contain the name of the social backend to be used
        if request.backend is None:
            raise errors.InvalidRequestError(
                description='Missing backend parameter.',
                request=request)

        # Code received from the client that in turn received it from
        # an authentication provider
        if request.code is None:
            raise errors.InvalidRequestError(
                description='Missing code parameter.', request=request)

        if not request.client_id:
            raise errors.MissingClientIdError(request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(request=request)

        for param in ('client_id', 'grant_type'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param,
                                                 request=request)

        if self.request_validator.client_authentication_required(request):
            if not self.request_validator.authenticate_client(request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        if not hasattr(request.client, 'client_id'):
            raise NotImplementedError('Authenticate client must set the '
                                      'request.client.client_id attribute '
                                      'in authenticate_client.')

        request.client_id = request.client_id or request.client.client_id

        # A random string value to hold state between our backend request and response.
        # Example: https://developers.google.com/identity/protocols/OpenIDConnect#createxsrftoken
        request.state = hashlib.sha256(os.urandom(1024)).hexdigest()

        # Ensure client is authorized use of this grant type
        # Note: this is overriden to support the base class. Also see comment
        # in ConvertAccessTokenGrant.
        request.grant_type = 'refresh_token'
        self.validate_grant_type(request)

        self.validate_scopes(request)

        # Set redirect_uri to redirect back to our API once authorization
        # code is converted into an access token
        default_redirect_uri = reverse('%s:%s:complete' % (DRFSO2_URL_NAMESPACE, NAMESPACE) , args=(request.backend,))
        request.redirect_uri = default_redirect_uri
        request.using_default_redirect_uri = True

        # TODO: Find a better way to pass the django request object
        strategy = load_strategy(request=request.django_request)

        try:
            backend = load_backend(strategy, request.backend, request.redirect_uri)
        except MissingBackend:
            raise errors.InvalidRequestError(
                description='Invalid backend parameter.',
                request=request)

        backend.data['code'] = request.code
        backend.data['state'] = request.state

        try:
            user = backend.auth_complete()
        except requests.HTTPError as e:
            raise errors.InvalidRequestError(
                description='Backend responded with HTTP{0}: {1}.'.format(e.response.status_code,
                                                                          e.response.text),
                request=request)
        except SocialAuthBaseException as e:
            raise errors.AccessDeniedError(description=str(e), request=request)

        if not user:
            raise errors.InvalidGrantError('Invalid credentials given.', request=request)

        if not user.is_active:
            raise errors.InvalidGrantError('User inactive or deleted.', request=request)
        
        request.user = user
        log.debug('Authorizing access to user %r.', request.user)


class ConvertAccessTokenGrant(RefreshTokenGrant):

    """This grant type validates access_token received from a third-party
    authentication backend and converts it to a social token.

    Uses `Refresh token grant`_ as the base.
    .. _`Refresh token grant`: http://tools.ietf.org/html/rfc6749#section-6
    """

    def validate_token_request(self, request):
        # This method's code is based on the parent method's code
        # We removed the original comments to replace with ours
        # explaining our modifications.

        # We are going to need to set these as None by default
        # to avoid AttributeError later
        request._params.setdefault('backend', None)
        request._params.setdefault('client_secret', None)

        if request.grant_type != 'convert_token':
            raise errors.UnsupportedGrantTypeError(request=request)

        # We check that a token parameter is present.
        # It should contain the social token to be used with the backend
        if request.token is None:
            raise errors.InvalidRequestError(
                description='Missing token parameter.',
                request=request)

        # We check that a backend parameter is present.
        # It should contain the name of the social backend to be used
        if request.backend is None:
            raise errors.InvalidRequestError(
                description='Missing backend parameter.',
                request=request)

        if not request.client_id:
            raise errors.MissingClientIdError(request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise errors.InvalidClientIdError(request=request)

        # Existing code to retrieve the application instance from the client id
        if self.request_validator.client_authentication_required(request):
            log.debug('Authenticating client, %r.', request)
            if not self.request_validator.authenticate_client(request):
                log.debug('Invalid client (%r), denying access.', request)
                raise errors.InvalidClientError(request=request)
        elif not self.request_validator.authenticate_client_id(request.client_id, request):
            log.debug('Client authentication failed, %r.', request)
            raise errors.InvalidClientError(request=request)

        # Ensure client is authorized use of this grant type
        # We chose refresh_token as a grant_type
        # as we don't want to modify all the codebase.
        # It is also the most permissive and logical grant for our needs.
        request.grant_type = 'refresh_token'
        self.validate_grant_type(request)

        self.validate_scopes(request)

        # TODO: Find a better way to pass the django request object
        strategy = load_strategy(request=request.django_request)

        try:
            backend = load_backend(strategy, request.backend,
                                   reverse('%s:%s:complete' % (DRFSO2_URL_NAMESPACE, NAMESPACE) , args=(request.backend,)))
        except MissingBackend:
            raise errors.InvalidRequestError(
                description='Invalid backend parameter.',
                request=request)

        try:
            user = backend.do_auth(access_token=request.token)
        except requests.HTTPError as e:
            raise errors.InvalidRequestError(
                description='Backend responded with HTTP{0}: {1}.'.format(e.response.status_code,
                                                                          e.response.text),
                request=request)
        except SocialAuthBaseException as e:
            raise errors.AccessDeniedError(description=str(e), request=request)

        if not user:
            raise errors.InvalidGrantError('Invalid credentials given.', request=request)

        if not user.is_active:
            raise errors.InvalidGrantError('User inactive or deleted.', request=request)
        
        request.user = user
        log.debug('Authorizing access to user %r.', request.user)
