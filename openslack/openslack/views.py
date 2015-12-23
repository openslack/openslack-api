from rest_framework.decorators import api_view, authentication_classes, permission_classes, parser_classes, \
    renderer_classes,detail_route, list_route
from rest_framework.views import APIView
from rest_framework.generics import RetrieveAPIView,ListCreateAPIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from rest_framework import exceptions
from oauth2_provider.ext.rest_framework import OAuth2Authentication
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.throttling import UserRateThrottle
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer,TemplateHTMLRenderer,BrowsableAPIRenderer,AdminRenderer
from .models import CommentSerializer
from rest_framework import filters


class ListUsers(APIView):
    """
    View to list all users in the system.

    * Requires token authentication.
    * Only admin users are able to access this view.
    """
    authentication_classes = (authentication.TokenAuthentication,)
    permission_classes = (permissions.IsAdminUser,)
    renderer_classes = (JSONRenderer, )
    parser_classes = (JSONParser, )

    def get(self, request, format=None):
        """
        Return a list of all users.
        """
        usernames = [user.username for user in User.objects.all()]
        return Response(usernames)


class OncePerDayUserThrottle(UserRateThrottle):
    rate = '1/day'  # 限制一天访问一次


# @api_view(['GET', 'POST'])
@api_view()
@authentication_classes([OAuth2Authentication])
@permission_classes([permissions.IsAuthenticated])
@throttle_classes([OncePerDayUserThrottle])  # 限流一天一次
@parser_classes((JSONParser,))
@renderer_classes((JSONRenderer,))
def hello_world(request):
    return Response({"message": "Hello, world!"})


class ExampleAuthentication(OAuth2Authentication):
    def authenticate(self, request):
        username = request.META.get('X_USERNAME')
        if not username:
            return None

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed('No such user')

        return (user, None)


def empty_view(self):
    content = {'please move along': 'nothing to see here'}
    return Response(content, status=status.HTTP_404_NOT_FOUND)


class UserDetail(RetrieveAPIView):
    """
    A view that returns a templated HTML representation of a given user.
    """
    queryset = User.objects.all()
    renderer_classes = (TemplateHTMLRenderer,BrowsableAPIRenderer)

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        return Response({'user': self.object}, template_name='user_detail.html')

@api_view(('GET',))
@renderer_classes((TemplateHTMLRenderer, JSONRenderer))
def list_users1(request):
    """
    A view that can return JSON or HTML representations
    of the users in the system.
    """
    queryset = User.objects.filter(active=True)

    if request.accepted_renderer.format == 'html':
        # TemplateHTMLRenderer takes a context dict,
        # and additionally requires a 'template_name'.
        # It does not require serialization.
        data = {'users': queryset}
        return Response(data, template_name='list_users.html')

    # JSONRenderer requires serialized data as normal.
    serializer = CommentSerializer(instance=queryset)
    data = serializer.data
    return Response(data)

import django_filters
import api.permissions
class UserFilter(django_filters.FilterSet):
    username = django_filters.CharFilter(name="price", lookup_type='gte')
    email = django_filters.CharFilter(name="price", lookup_type='lte')
    class Meta:
        model = User
        fields = ['username', 'email', "first_name"]

class IsOwnerFilterBackend(filters.BaseFilterBackend):
    """
    Filter that only allows users to see their own objects.
    """
    def filter_queryset(self, request, queryset, view):
        return queryset.filter(owner=request.user)

class UserList(ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = CommentSerializer
    permission_classes = (permissions.IsAdminUser, api.permissions.CustomObjectPermissions,)
    filter_backends = (filters.DjangoFilterBackend,filters.SearchFilter,filters.OrderingFilter,IsOwnerFilterBackend)
    filter_fields = ('username', 'email', "first_name")
    search_fields = ('username', 'email')
    ordering_fields = ('username', 'email')
    ordering = ('username',)

    def get_paginate_by(self):
        """
        Use smaller pagination for HTML representations.
        """
        if self.request.accepted_renderer.format == 'html':
            return 20
        return 100

    def get_queryset(self):
        user = self.request.user
        users=user.accounts.all()
        username = self.request.query_params.get('username', None)
        if username is not None:
            queryset = users.filter(purchaser__username=username)
        return queryset

    def get_object(self):
        queryset = self.get_queryset()
        filter = {}
        for field in self.multiple_lookup_fields:
            filter[field] = self.kwargs[field]

        obj = get_object_or_404(queryset, **filter)
        self.check_object_permissions(self.request, obj)
        return obj

    def filter_queryset(self, queryset):
        filter_backends = (UserFilter,)

        if 'geo_route' in self.request.query_params:
            filter_backends = (GeoRouteFilter, CategoryFilter)
        elif 'geo_point' in self.request.query_params:
            filter_backends = (GeoPointFilter, CategoryFilter)

        for backend in list(filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, view=self)

        return queryset

    def get_serializer_class(self):
        if self.request.user.is_staff:
            return FullAccountSerializer
        return BasicAccountSerializer

    def perform_create(self, serializer):
        queryset = SignupRequest.objects.filter(user=self.request.user)
        if queryset.exists():
            raise ValidationError('You have already signed up')
        serializer.save(user=self.request.user)

    def perform_update(self, serializer):
        instance = serializer.save()
        send_email_confirmation(user=self.request.user, modified=instance)

    def list(self, request):
        # Note the use of `get_queryset()` instead of `self.queryset`
        queryset = self.get_queryset()
        serializer = CommentSerializer(queryset, many=True)
        return Response(serializer.data)

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter


class UserViewSet(viewsets.ViewSet):
    """
    A simple ViewSet for listing or retrieving users.
    """
    def list(self, request):
        queryset = User.objects.all()
        serializer = CommentSerializer(queryset, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        queryset = User.objects.all()
        user = get_object_or_404(queryset, pk=pk)
        serializer = CommentSerializer(user)
        return Response(serializer.data)

    def create(self, request):
        pass

    def update(self, request, pk=None):
        pass

    def partial_update(self, request, pk=None):
        pass

    def destroy(self, request, pk=None):
        pass

    @detail_route(methods=['post'])
    @detail_route(methods=['post'], permission_classes=[IsAdminOrIsSelf]) #^users/{pk}/change-password/$ Name: 'user-change-password'
    def set_password(self, request, pk=None):
        user = self.get_object()
        serializer = PasswordSerializer(data=request.data)
        if serializer.is_valid():
            user.set_password(serializer.data['password'])
            user.save()
            return Response({'status': 'password set'})
        else:
            return Response(serializer.errors,
                            status=status.HTTP_400_BAD_REQUEST)

    @detail_route(methods=['post', 'delete']) #^users/{pk}/set_password/$ and ^users/{pk}/unset_password/$
    def unset_password(self, request, pk=None):
        return Response({'status': 'password unset'})

    @list_route()
    def recent_users(self, request):
        recent_users = User.objects.all().order('-last_login')

        page = self.paginate_queryset(recent_users)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(recent_users, many=True)
        return Response(serializer.data)

from rest_framework.mixins import CreateModelMixin,ListModelMixin,RetrieveModelMixin
class AccountViewSet(viewsets.ModelViewSet):
    """
    A simple ViewSet for viewing and editing the accounts
    associated with the user.
    """
    serializer_class = CommentSerializer
    permission_classes = [IsAccountAdminOrReadOnly]
    queryset = User.objects.all()

    def get_queryset(self):
        return self.request.user.accounts.all()

class AccountViewSet(CreateModelMixin,ListModelMixin,RetrieveModelMixin,viewsets.GenericViewSet):
    """
    A viewset that provides `retrieve`, `create`, and `list` actions.

    To use it, override the class and set the `.queryset` and
    `.serializer_class` attributes.
    """
    pass

user_list = UserViewSet.as_view({'get': 'list'})
user_detail = UserViewSet.as_view({'get': 'retrieve'})

router = DefaultRouter()
router.register(r'users', UserViewSet)
urlpatterns = router.urls

from rest_framework.routers import Route, DynamicDetailRoute, SimpleRouter
class CustomReadOnlyRouter(SimpleRouter):
    """
    A router for read-only APIs, which doesn't use trailing slashes.
    """
    routes = [
        Route(
            url=r'^{prefix}$',
            mapping={'get': 'list'},
            name='{basename}-list',
            initkwargs={'suffix': 'List'}
        ),
        Route(
            url=r'^{prefix}/{lookup}$',
           mapping={'get': 'retrieve'},
           name='{basename}-detail',
           initkwargs={'suffix': 'Detail'}
        ),
        DynamicDetailRoute(
            url=r'^{prefix}/{lookup}/{methodnamehyphen}$',
            name='{basename}-{methodnamehyphen}',
            initkwargs={}
        )
    ]

class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    A viewset that provides the standard actions
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'username'

    @detail_route()
    def group_names(self, request):
        """
        Returns a list of all the group names that the given
        user belongs to.
        """
        user = self.get_object()
        groups = user.groups.all()
        return Response([group.name for group in groups])

router = CustomReadOnlyRouter()
router.register('users', UserViewSet)
urlpatterns = router.urls
# URL Style	HTTP Method	Action	URL Name
# {prefix}/	GET	list	{basename}-list
# POST	create
# {prefix}/{methodname}/	GET, or as specified by `methods` argument	`@list_route` decorated method	{basename}-{methodname}
# {prefix}/{lookup}/	GET	retrieve	{basename}-detail
# PUT	update
# PATCH	partial_update
# DELETE	destroy
# {prefix}/{lookup}/{methodname}/	GET, or as specified by `methods` argument	`@detail_route` decorated method	{basename}-{methodname}