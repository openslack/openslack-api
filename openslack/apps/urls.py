from django.conf.urls import patterns, url, include
from django.contrib import admin
from django.conf import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.conf.urls.static import static

admin.autodiscover()

urlpatterns = patterns('',
    # url(r'^wanglingling/', include(admin.site.urls)),
)
